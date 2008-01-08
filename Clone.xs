#define PERL_NO_GET_CONTEXT

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include "ptable.h"

/*

   The clone_foo() functions make an exact copy of an existing foo thingy.
   During the course of a cloning, a hash table is used to map old addresses
   to new addresses. The table is created and manipulated with the
   PTABLE_* functions in ptable.h.

*/

#define clone_sv_inc(src, cache) SvREFCNT_inc(clone_sv(aTHX_ src, cache))

#define SAVEPV(p) (p ? savepv(p) : Nullch)
#define SAVEPVN(p,n) (p ? savepvn(p,n) : Nullch)
#define new_HE() new_he(aTHX)

#define CLONE_COPY_STASH(src, dest) (SvSTASH(dest) = (HV *)SvREFCNT_inc(SvSTASH(src)))

#ifdef PERL_MAGIC_backref
#define WEAKREF_IDENTIFIER PERL_MAGIC_backref
#else
#define WEAKREF_IDENTIFIER '<'
#endif

#define CLONE_SHAREPVN(sv, len, hash) (HEK_KEY(share_hek(sv, len, hash)))

/*
 * chocolateboy
 *
 * Not every reference that refers to a weak referent is weak. For instance, in:
 *
 *     $test = [ undef ];
 *     weaken($test->[0] = $test);
 *
 * $test is not a weakref, but $test->[0] is.
 *
 * However, all weak references refer to weak referents.
 *
 * Thus we can save a little time by telling clone_sv that the referent is weak,
 * which prevents it consulting the sv's magic
 */

#define CLONE_RVPV(src, dest)							    \
STMT_START {                                                                        \
    if (SvROK(src)) {                                                               \
        SvRV(dest) = SvWEAKREF(src) ?                                               \
            clone_sv(aTHX_ SvRV(src), TRUE) :					    \
            clone_sv_inc(SvRV(src), FALSE);					    \
    } else if (SvPVX(src)) {							    \
        /* Has something there */                                                   \
        if (SvLEN(src)) {                                                           \
            /* Normal PV - clone whole allocated space */                           \
            SvPVX(dest) = SAVEPVN(SvPVX(src), SvLEN(src)-1);                        \
        } else {                                                                    \
            /* Special case - not normally malloced for some reason */              \
            if (SvREADONLY(src) && SvFAKE(src)) {                                   \
                /* A "shared" PV */                                                 \
                SvPVX(dest) = CLONE_SHAREPVN(SvPVX(src), SvCUR(src), SvUVX(src));   \
                SvUVX(dest) = SvUVX(src);                                           \
            } else {                                                                \
                /* Some other special case - random pointer */                      \
                SvPVX(dest) = SvPVX(src);                                           \
            }                                                                       \
        }                                                                           \
    } else {                                                                        \
        /* Copy the Null */                                                         \
        SvPVX(dest) = SvPVX(src);                                                   \
    }                                                                               \
} STMT_END

static PTABLE_t *PTABLE;

static SV * clone_sv(pTHX_ SV *src, I32 cache);
static MAGIC * clone_mg(pTHX_ MAGIC *mg);

static HE * new_he(pTHX);
static void more_he(pTHX);
static HEK * save_hek_flags(const char *str, I32 len, U32 hash, int flags);
static HE * clone_he(pTHX_ HE *e, bool shared);
static HEK * share_hek_flags(pTHX_ const char *str, I32 len, register U32 hash, int flags);

/*
 * chocolateboy
 *
 * share_hek wasn't made public till 5.8.8
 */

#ifndef share_hek
/* get a (constant) string ptr from the global string table
 * string will get added if it is not already there.
 * len and hash must both be valid for str.
 */

static HEK *
clone_share_hek(pTHX_ const char *str, I32 len, register U32 hash)
{
    bool is_utf8 = FALSE;
    int flags = 0;
    const char * const save = str;

    if (len < 0) {
      STRLEN tmplen = -len;
      is_utf8 = TRUE;
      /* See the note in hv_fetch(). --jhi */
      str = (char*)bytes_from_utf8((U8*)str, &tmplen, &is_utf8);
      len = tmplen;
      /* If we were able to downgrade here, then than means that we were passed
         in a key which only had chars 0-255, but was utf8 encoded.  */
      if (is_utf8)
          flags = HVhek_UTF8;
      /* If we found we were able to downgrade the string to bytes, then
         we should flag that it needs upgrading on keys or each.  Also flag
         that we need share_hek_flags to free the string.  */
      if (str != save)
          flags |= HVhek_WASUTF8 | HVhek_FREEKEY;
    }

    return share_hek_flags (aTHX_ str, len, hash, flags);
}
#define share_hek(str, len, hash) (clone_share_hek(aTHX_ str, len, hash))
#endif

static HEK * save_hek_flags(const char *str, I32 len, U32 hash, int flags) {
    int flags_masked = flags & HVhek_MASK;
    char *k;
    register HEK *hek;

    Newx(k, HEK_BASESIZE + len + 2, char);
    hek = (HEK*)k;
    Copy(str, HEK_KEY(hek), len, char);
    HEK_KEY(hek)[len] = 0;
    HEK_LEN(hek) = len;
    HEK_HASH(hek) = hash;
    HEK_FLAGS(hek) = (unsigned char)flags_masked;

    if (flags & HVhek_FREEKEY)
	Safefree(str);

    return hek;
}

static HEK * share_hek_flags(pTHX_ const char *str, I32 len, register U32 hash, int flags) {
    register XPVHV* xhv;
    register HE *entry;
    register HE **oentry;
    register I32 i = 1;
    I32 found = 0;
    int flags_masked = flags & HVhek_MASK;

    /* what follows is the moral equivalent of:

       if (!(Svp = hv_fetch(PL_strtab, str, len, TRUE)))
       hv_store(PL_strtab, str, len, Nullsv, hash);

       Can't rehash the shared string table, so not sure if it's worth
       counting the number of entries in the linked list
     */
    xhv = (XPVHV*)SvANY(PL_strtab);
    LOCK_STRTAB_MUTEX;
    /* oentry = &(HvARRAY(hv))[hash & (I32) HvMAX(hv)]; */                                                                   
    oentry = &((HE**)xhv->xhv_array)[hash & (I32) xhv->xhv_max];
    for (entry = *oentry; entry; i = 0, entry = HeNEXT(entry)) {
	if (HeHASH(entry) != hash) /* strings can't be equal */
	    continue;
	if (HeKLEN(entry) != len)
	    continue;
	if (HeKEY(entry) != str && memNE(HeKEY(entry),str,len)) /* is this it? */
	    continue;
	if (HeKFLAGS(entry) != flags_masked)
	    continue;
	found = 1;
	++HeVAL(entry); /* use value slot as REFCNT */
	break;
    }

    UNLOCK_STRTAB_MUTEX;

    if (flags & HVhek_FREEKEY)
	Safefree(str);

    /* 
     * chocolateboy
     * 
     * We can bypass the call to hsplit (which requires a lot of potentially volatile code to be inlined)
     * if we enforce the rule that shared keys are still shared. Two obvious violations of this would be
     * a) a HASH with invalid flags (i.e. its keys, for some reason, are not really shared) and b) invocation
     * of clone after the shared string table has been freed (e.g. during global destruction)
     */

    if (!found)
	Perl_croak(aTHX_ "can't find shared key in string table");

    return HeKEY_hek(entry);
}

static HE* new_he(pTHX) {
    HE* he;
    LOCK_SV_MUTEX;
    if (!PL_he_root)
	more_he(aTHX);
    he = PL_he_root;
    PL_he_root = HeNEXT(he);
    UNLOCK_SV_MUTEX;
    return he;
}

static void more_he(pTHX) {
    register HE* he;
    register HE* heend;
    XPV *ptr;
    Newx(ptr, 1008 / sizeof(XPV), XPV);
    ptr->xpv_pv = (char*)PL_he_arenaroot;
    PL_he_arenaroot = ptr;

    he = (HE*)ptr;
    heend = &he[1008 / sizeof(HE) - 1];
    PL_he_root = ++he;
    while (he < heend) {
	HeNEXT(he) = (HE*)(he + 1);
	he++;
    }
    HeNEXT(he) = 0;
}

static HE * clone_he(pTHX_ HE *e, bool shared) {
    HE *ret = NULL;

    /* create anew and remember what it is */
    ret = new_HE();

    HeNEXT(ret) = HeNEXT(e) ? clone_he(aTHX_ HeNEXT(e), shared) : Nullhe;

    if (HeKLEN(e) == HEf_SVKEY) {
	char *k;
	Newx(k, HEK_BASESIZE + sizeof(SV*), char);
	HeKEY_hek(ret) = (HEK*)k;
	HeKEY_sv(ret) = SvREFCNT_inc(clone_sv(aTHX_ HeKEY_sv(e), FALSE));
    } else if (shared) {
	HeKEY_hek(ret) = share_hek_flags(aTHX_ HeKEY(e), HeKLEN(e), HeHASH(e), HeKFLAGS(e));
    } else {
	HeKEY_hek(ret) = save_hek_flags(HeKEY(e), HeKLEN(e), HeHASH(e), HeKFLAGS(e));
    }

    HeVAL(ret) = SvREFCNT_inc(clone_sv(aTHX_ HeVAL(e), FALSE));
    return ret;
}

/* duplicate a chain of magic */

static MAGIC * clone_mg(pTHX_ MAGIC *mg) {
    MAGIC *mgprev = (MAGIC*)NULL;
    MAGIC *mgret = NULL;

    if (!mg)
	return (MAGIC*)NULL;

    for (; mg; mg = mg->mg_moremagic) {
	MAGIC *nmg;
	Newxz(nmg, 1, MAGIC);

	if (mgprev) {
	    mgprev->mg_moremagic = nmg;
	} else {
	    mgret = nmg;
	}

	nmg->mg_virtual	= mg->mg_virtual; /* XXX copy dynamic vtable? */
	nmg->mg_private	= mg->mg_private;
	nmg->mg_type	= mg->mg_type;
	nmg->mg_flags	= mg->mg_flags;

	if (mg->mg_type == WEAKREF_IDENTIFIER) {
	    AV *av = (AV*) mg->mg_obj;
	    SV **svp;
	    I32 i;

	    /*
		chocolateboy

		The refcount of the backrefs array changed from 1 to 2 in 2003.

		We can improve backwards compatibility by copying the refcount instead
		of fixing it at the current default.
	    */

	    /* SvREFCNT_inc(nmg->mg_obj = (SV*)newAV()); */
	    nmg->mg_obj = (SV*)newAV();
	    SvREFCNT(nmg->mg_obj) = SvREFCNT(mg->mg_obj);

	    svp = AvARRAY(av);
	    for (i = AvFILLp(av); i >= 0; --i) {
		if (!svp[i]) continue;
		av_push((AV*)nmg->mg_obj, clone_sv_inc(svp[i], TRUE));
	    }
	} else {
            /*
             * chocolateboy
             * 
             * Another exception to the rule that SVs with a refcount < 2 don't
             * need to be cached - some magical SVs bypass the standard refcounting
             * mechanism.
             */
	    nmg->mg_obj	= (mg->mg_flags & MGf_REFCOUNTED)
		? clone_sv_inc(mg->mg_obj, TRUE)
		: clone_sv(aTHX_ mg->mg_obj, TRUE); /* XXX chocolateboy: for some reason, this must be cached */
	}
	nmg->mg_len = mg->mg_len;
	nmg->mg_ptr = mg->mg_ptr; /* XXX random ptr? */

	if (mg->mg_ptr && mg->mg_type != PERL_MAGIC_regex_global) {
	    if (mg->mg_len > 0) {
		nmg->mg_ptr = SAVEPVN(mg->mg_ptr, mg->mg_len);
		if (mg->mg_type == PERL_MAGIC_overload_table && AMT_AMAGIC((AMT*)mg->mg_ptr)) {
		    AMT *amtp = (AMT*)mg->mg_ptr;
		    AMT *namtp = (AMT*)nmg->mg_ptr;
		    I32 i;
		    for (i = 1; i < NofAMmeth; i++) {
			namtp->table[i] = (CV *)SvREFCNT_inc((SV *)amtp->table[i]);
		    }
		}
	    } else if (mg->mg_len == HEf_SVKEY) {
		nmg->mg_ptr = (char*)clone_sv_inc((SV*)mg->mg_ptr, FALSE);
	    }
	}

	mgprev = nmg;
    }
    return mgret;
}

/* duplicate an SV of any type (including AV, HV etc) */

static SV * clone_sv(pTHX_ SV *src, I32 cache) {
    SV * dest;

    if (!src || SvTYPE(src) == SVTYPEMASK) {
	return Nullsv;
    }

    /* weakref magic is actually attached to the referent rather than the reference */
    if (!cache) {
	/* chocolateboy: don't involve the cache if the refcnt < 2 unless forced */
	if ((SvREFCNT(src) > 1) || (SvROK(src) && SvWEAKREF(src)) || (SvMAGICAL(src) && mg_find(src, WEAKREF_IDENTIFIER))) {
	    cache = 1;
	}
    }

    /* warn ("cache: %d, refcnt: %d, weakref: %d", cache, SvREFCNT(src), is_weakref); */
    /* look for it in the cache first */
    if (cache) {
	dest = (SV*)PTABLE_fetch(PTABLE, src);

	if (dest) {
	    return dest;
	}
    }

    dest = newSV(0);

    /* don't propagate OOK hack or context-specific flags */

    /*
        chocolateboy
        
        SVpad_OUR conflicts with SvWEAKREF, so we can't turn that off:

            SvFLAGS(dest) &= ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVs_TEMP | SVpad_OUR);

	also note: we can't factor out the flag copying (by placing it here) because the flags
	influence SvUPGRADE
    */      

    SvREFCNT(dest) = 0;

    if (cache) {
	PTABLE_store(PTABLE, src, dest);
    }

    switch (SvTYPE(src)) {
	case SVt_NULL:
	    /* warn("SVt_NULL"); */
	    /* FIXME: already null */
	    (void)SvUPGRADE(dest, SVt_NULL);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    break;
	case SVt_IV:
	    /* warn("SVt_IV"); */
	    (void)SvUPGRADE(dest, SVt_IV);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    SvIVX(dest) = SvIVX(src);
	    break;
	case SVt_NV:
	    /* warn("SVt_NV"); */
	    (void)SvUPGRADE(dest, SVt_NV);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    SvNVX(dest) = SvNVX(src);
	    break;
	case SVt_RV:
	    /* warn("SVt_RV"); */
	    (void)SvUPGRADE(dest, SVt_RV);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    CLONE_RVPV(src, dest);
	    break;
	case SVt_PV:
	    /* warn("SVt_PV"); */
	    (void)SvUPGRADE(dest, SVt_PV);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    SvCUR(dest)     = SvCUR(src);
	    SvLEN(dest)     = SvLEN(src);
	    CLONE_RVPV(src, dest);
	    break;
	case SVt_PVIV:
	    /* warn("SVt_PVIV"); */
	    (void)SvUPGRADE(dest, SVt_PVIV);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    SvCUR(dest)	= SvCUR(src);
	    SvLEN(dest)	= SvLEN(src);
	    SvIVX(dest)	= SvIVX(src);
	    CLONE_RVPV(src, dest);
	    break;
	case SVt_PVNV:
	    /* warn("SVt_PVNV"); */
	    (void)SvUPGRADE(dest, SVt_PVNV);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    SvCUR(dest)	= SvCUR(src);
	    SvLEN(dest)	= SvLEN(src);
	    SvIVX(dest)	= SvIVX(src);
	    SvNVX(dest)	= SvNVX(src);
	    CLONE_RVPV(src, dest);
	    break;
	case SVt_PVMG:
	    /* warn("SVt_PVMG"); */
	    {
		/* FIXME: mg_find */
		MAGIC *mg = SvMAGIC(src);

		if (mg && mg->mg_type == PERL_MAGIC_qr) {
		    sv_clear(dest);
		    return src;
		}
	    }

	    (void)SvUPGRADE(dest, SVt_PVMG);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    SvCUR(dest)	= SvCUR(src);
	    SvLEN(dest)	= SvLEN(src);
	    SvIVX(dest)	= SvIVX(src);
	    SvNVX(dest)	= SvNVX(src);
	    SvMAGIC(dest) = clone_mg(aTHX_ SvMAGIC(src));
	    CLONE_COPY_STASH(src, dest);
	    CLONE_RVPV(src, dest);
	    break;
	case SVt_PVBM:
	    /* warn("SVt_PVBM"); */
	    (void)SvUPGRADE(dest, SVt_PVBM);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    SvCUR(dest)	= SvCUR(src);
	    SvLEN(dest)	= SvLEN(src);
	    SvIVX(dest)	= SvIVX(src);
	    SvNVX(dest)	= SvNVX(src);
	    SvMAGIC(dest) = clone_mg(aTHX_ SvMAGIC(src));
	    CLONE_COPY_STASH(src, dest);
	    CLONE_RVPV(src, dest);
	    BmRARE(dest) = BmRARE(src);
	    BmUSEFUL(dest) = BmUSEFUL(src);
	    BmPREVIOUS(dest) = BmPREVIOUS(src);
	    break;
	case SVt_PVLV:
	    /* warn("SVt_PVLV"); */
	    (void)SvUPGRADE(dest, SVt_PVLV);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    SvCUR(dest) = SvCUR(src);
	    SvLEN(dest) = SvLEN(src);
	    SvIVX(dest) = SvIVX(src);
	    SvNVX(dest) = SvNVX(src);
	    SvMAGIC(dest) = clone_mg(aTHX_ SvMAGIC(src));
	    CLONE_COPY_STASH(src, dest);
	    CLONE_RVPV(src, dest);
	    LvTARGOFF(dest) = LvTARGOFF(src); /* XXX sometimes holds PMOP* when DEBUGGING */
	    LvTARGLEN(dest) = LvTARGLEN(src);
	    if (LvTYPE(src) == 't') { /* for tie: unrefcnted fake (SV**) */
		LvTARG(dest) = dest;
	    } else if (LvTYPE(src) == 'T') { /* for tie: fake HE */
		LvTARG(dest) = LvTARG(src) ? (SV*)clone_he(aTHX_ (HE*)LvTARG(src), 0) : (SV*)Nullhe;
	    } else {
		LvTARG(dest) = clone_sv_inc(LvTARG(src), FALSE);
	    }
	    LvTYPE(dest) = LvTYPE(src);
	    break;
	case SVt_PVAV:
	    /* warn("SVt_PVAV"); */
	    (void)SvUPGRADE(dest, SVt_PVAV);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    SvCUR(dest)	= SvCUR(src);
	    SvLEN(dest)	= SvLEN(src);
	    SvIVX(dest)	= SvIVX(src);
	    SvNVX(dest)	= SvNVX(src);
	    SvMAGIC(dest) = clone_mg(aTHX_ SvMAGIC(src));
	    CLONE_COPY_STASH(src, dest);
	    AvARYLEN((AV*)dest) = clone_sv_inc(AvARYLEN((AV*)src), FALSE);
	    AvFLAGS((AV*)dest) = AvFLAGS((AV*)src);

	    if (AvARRAY((AV*)src)) {
		SV **dst_ary, **src_ary;
		SSize_t items = AvFILLp((AV*)src) + 1;

		src_ary = AvARRAY((AV*)src);
		Newxz(dst_ary, AvMAX((AV*)src)+1, SV*);
		PTABLE_store(PTABLE, src_ary, dst_ary); /* XXX */
		SvPVX(dest) = (char*)dst_ary;
		AvALLOC((AV*)dest) = dst_ary;
		if (AvREAL((AV*)src)) {
		    while (items-- > 0)
			*dst_ary++ = clone_sv_inc(*src_ary++, FALSE);
		} else {
		    while (items-- > 0)
			*dst_ary++ = clone_sv(aTHX_ *src_ary++, FALSE);
		}
		items = AvMAX((AV*)src) - AvFILLp((AV*)src);
		while (items-- > 0) {
		    *dst_ary++ = &PL_sv_undef;
		}
	    } else {
		SvPVX(dest)		= Nullch;
		AvALLOC((AV*)dest)	= (SV**)NULL;
	    }
	    if (SvMAGICAL(src)) {
		assert(SvMAGICAL(dest));
	    }
	    break;
	case SVt_PVHV:
	    /* warn("SVt_PVHV"); */
	    (void)SvUPGRADE(dest, SVt_PVHV);
	    SvFLAGS(dest) = SvFLAGS(src) & ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);
	    SvCUR(dest) = SvCUR(src);
	    SvLEN(dest) = SvLEN(src);
	    SvIVX(dest) = SvIVX(src);
	    SvNVX(dest) = SvNVX(src);
	    SvMAGIC(dest) = clone_mg(aTHX_ SvMAGIC(src));
	    CLONE_COPY_STASH(src, dest);
	    HvRITER((HV*)dest) = HvRITER((HV*)src);
	    if (HvARRAY((HV*)src)) {
		STRLEN i = 0;
		XPVHV *dxhv = (XPVHV*)SvANY(dest);
		XPVHV *sxhv = (XPVHV*)SvANY(src);
		Newxz(dxhv->xhv_array, PERL_HV_ARRAY_ALLOC_BYTES(dxhv->xhv_max+1), char);

		while (i <= sxhv->xhv_max) {
		    HE* he = ((HE**)sxhv->xhv_array)[i];
		    ((HE**)dxhv->xhv_array)[i] =
			he ? clone_he(aTHX_ he, (bool)!!HvSHAREKEYS(src)) : Nullhe;
		    ++i;
		}

		dxhv->xhv_eiter = sxhv->xhv_eiter ?
		    clone_he(aTHX_ sxhv->xhv_eiter, (bool)!!HvSHAREKEYS(src)) :
		    Nullhe;
	    }

	    /* 
	       chocolateboy

	       set by sv_upgrade

	       else {
	       SvPVX(dest) = Nullch; 
	       HvEITER((HV*)dest) = (HE*)NULL;
	       }
	     */
	    HvPMROOT((HV*)dest) = HvPMROOT((HV*)src); /* XXX */
	    HvNAME((HV*)dest) = SAVEPV(HvNAME((HV*)src));
	    /* Record stashes for possible cloning in Perl_clone(). */
	    /*
	      chocolateboy

	      if(HvNAME((HV*)dest))
	       av_push(param->stashes, dest);
	     */
	    break;
	case SVt_PVFM:
	case SVt_PVCV:
	case SVt_PVGV:
	case SVt_PVIO:
	    /* warn("SVt_PVFM or SVt_PVCV or SVt_PVGV or SVt_PVIO"); */
	    sv_clear(dest);
	    return src;
	    break;
	default:
	    Perl_croak(aTHX_ "Bizarre SvTYPE [%" IVdf "]", (IV)SvTYPE(src));
	    break;
    }

    if (SvOBJECT(dest) && (SvTYPE(dest) != SVt_PVIO))
	++PL_sv_objcount;

    return dest;
}

MODULE = Scalar::Util::Clone		PACKAGE = Scalar::Util::Clone

PROTOTYPES: ENABLE

BOOT:
PTABLE = PTABLE_new();
if (!PTABLE) croak ("Can't initialize pointer table (PTABLE)");

void
END()
    PROTOTYPE:
    CODE:
	PTABLE_free(PTABLE);

void
clone(original)
    SV *original
    PROTOTYPE: $
    PREINIT:
	SV *clone;
    PPCODE:
	clone = clone_sv(aTHX_ original, FALSE);
	PTABLE_clear(PTABLE);

	EXTEND(SP,1);
	PUSHs(sv_2mortal(SvREFCNT_inc(clone)));
