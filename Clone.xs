#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"
#include "regcomp.h"

/*

   The clone_foo() functions make an exact copy of an existing foo thingy.
   During the course of a cloning, a hash table is used to map old addresses
   to new addresses. The table is created and manipulated with the
   ptr_table_* functions.

*/

#define clone_sv_inc(s,t) SvREFCNT_inc(clone_sv(s,t))
#define clone_av_inc(s,t) (AV*)SvREFCNT_inc(clone_sv((SV*)s,t))
#define clone_cv_inc(s,t) (CV*)SvREFCNT_inc(clone_sv((SV*)s,t))

#define SAVEPV(p) (p ? savepv(p) : Nullch)
#define SAVEPVN(p,n) (p ? savepvn(p,n) : Nullch)

/* PerlIO_printf(PerlIO_stderr(), ...) */
/* #define CLONE_DEBUG Perl_warn */
#define CLONE_DEBUG(...)

#ifdef PURIFY
#define new_HE() (HE*)safemalloc(sizeof(HE))
#else
#define new_HE() new_he()
#endif

#define CLONE_NEW_SV(sstr, dstr, ptr_table)				    											\
STMT_START {								    														\
	CLONE_DEBUG("    creating new SV\n");																\
	dstr = Perl_newSV(0);						    													\
	(void)SvUPGRADE(dstr, SvTYPE(sstr));				    											\
	SvFLAGS(dstr) = SvFLAGS(sstr);					    												\
	/* don't propagate OOK hack or context-specific flags */	    									\
	/* SVpad_OUR conflicts with SvWEAKREF */															\
	/* SvFLAGS(dstr) &= ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVs_TEMP | SVpad_OUR); */				\
	SvFLAGS(dstr) &= ~(SVs_PADBUSY | SVs_PADTMP | SVs_PADMY | SVf_OOK);									\
	SvREFCNT(dstr) = 0; /* must be before any other dups! */	    									\
	/* TODO */																							\
	/* SvTAINTED(dstr) = SvTAINTED(sstr);*/																\
	ptr_table_store(ptr_table, sstr, dstr);			    												\
} STMT_END

#define CLONE_PASS_THRU(sstr, dstr, ptr_table)				    										\
STMT_START {								    														\
	CLONE_DEBUG("    returning original sv\n");															\
	dstr = sstr;																						\
	/* dstr = SvREFCNT_inc(SvROK(sstr) ? SvRV(dstr) : dstr); */											\
	ptr_table_store(ptr_table, sstr, sstr);																\
} STMT_END

#define CLONE_COPY_STASH(sstr, dsrt) (SvSTASH(dstr) = (HV *)SvREFCNT_inc(SvSTASH(sstr)))

#ifdef SvWEAKREF
#ifdef PERL_MAGIC_backref
#define WEAKREF_IDENTIFIER PERL_MAGIC_backref
#else
#define WEAKREF_IDENTIFIER '<'
#endif
#endif

/* the Perl_sharepvn macro is public but references a private function - fix that */
#define CLONE_SHAREPVN(sv, len, hash) HEK_KEY(Perl_share_hek(sv, len, hash))

#if (PTRSIZE == 8)
#define PTR_TABLE_HASH(ptr) (PTR2UV(ptr) >> 3)
#else
#define PTR_TABLE_HASH(ptr) (PTR2UV(ptr) >> 2)
#endif

#ifdef PURIFY
#define new_HE() (HE*)safemalloc(sizeof(HE))
#else
#define new_HE() new_he()
#endif

static SV * clone_sv(SV *sstr, PTR_TBL_t *ptr_table);
static void clone_rvpv(SV *sstr, SV *dstr, PTR_TBL_t *ptr_table);
static REGEXP *clone_re(REGEXP *r, PTR_TBL_t *ptr_table);
static MAGIC * clone_mg(MAGIC *mg, PTR_TBL_t *ptr_table);

static PTR_TBL_t * ptr_table_new();
static void * ptr_table_fetch(PTR_TBL_t *tbl, void *sv);
static void ptr_table_store(PTR_TBL_t *tbl, void *oldv, void *newv);
static void ptr_table_grow(PTR_TBL_t *tbl);
static void ptr_table_clear(PTR_TBL_t *tbl);
static void ptr_table_free(PTR_TBL_t *tbl);

static HE* new_he(void);
static void more_he(void);
static HEK * save_hek_flags(const char *str, I32 len, U32 hash, int flags);
static HE * clone_he(HE *e, bool shared, PTR_TBL_t * ptr_table);
static HEK * share_hek_flags(const char *str, I32 len, register U32 hash, int flags);

static HEK *
save_hek_flags(const char *str, I32 len, U32 hash, int flags)
{
	int flags_masked = flags & HVhek_MASK;
	char *k;
	register HEK *hek;

	New(54, k, HEK_BASESIZE + len + 2, char);
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

static HEK *
share_hek_flags(const char *str, I32 len, register U32 hash, int flags)
{
	register XPVHV* xhv;
	register HE *entry;
	register HE **oentry;
	register I32 i = 1;
	I32 found = 0;
	int flags_masked = flags & HVhek_MASK;

	/* what follows is the moral equivalent of:

	   if (!(Svp = hv_fetch(PL_strtab, str, len, FALSE)))
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
	 * We can bypass the call to hsplit (which requires a lot of potentially volatile code to be inlined)
	 * if we enforce the rule that shared keys are still shared. Two obvious violations of this would be
	 * a) a HASH with invalid flags (i.e. its keys, for some reason, are not really shared) and b) invocation
	 * of clone after the shared string table has been freed (e.g. during global destruction)
	 */

	if (!found)
		Perl_croak("can't find shared key in string table");

	return HeKEY_hek(entry);
}

static HE*
new_he(void)
{
	HE* he;
	LOCK_SV_MUTEX;
	if (!PL_he_root)
		more_he();
	he = PL_he_root;
	PL_he_root = HeNEXT(he);
	UNLOCK_SV_MUTEX;
	return he;
}

static void
more_he(void)
{
	register HE* he;
	register HE* heend;
	XPV *ptr;
	New(54, ptr, 1008 / sizeof(XPV), XPV);
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

static HE *
clone_he(HE *e, bool shared, PTR_TBL_t * ptr_table)
{
	HE *ret;

	if (!e)
		return Nullhe;

	/* look for it in the table first */
	ret = (HE*)ptr_table_fetch(ptr_table, e);

	if (ret)
		return ret;

	/* create anew and remember what it is */
	ret = new_HE();
	ptr_table_store(ptr_table, e, ret);
	HeNEXT(ret) = clone_he(HeNEXT(e), shared, ptr_table);

	if (HeKLEN(e) == HEf_SVKEY) {
		char *k;
		New(54, k, HEK_BASESIZE + sizeof(SV*), char);
		HeKEY_hek(ret) = (HEK*)k;
		HeKEY_sv(ret) = SvREFCNT_inc(clone_sv(HeKEY_sv(e), ptr_table));
	} else if (shared) {
		HeKEY_hek(ret) = share_hek_flags(HeKEY(e), HeKLEN(e), HeHASH(e), HeKFLAGS(e));
	} else {
		HeKEY_hek(ret) = save_hek_flags(HeKEY(e), HeKLEN(e), HeHASH(e), HeKFLAGS(e));
	}

	HeVAL(ret) = SvREFCNT_inc(clone_sv(HeVAL(e), ptr_table));
	return ret;
}

/* create a new pointer-mapping table */

static PTR_TBL_t *
ptr_table_new()
{
	PTR_TBL_t *tbl;
	Newz(0, tbl, 1, PTR_TBL_t);
	tbl->tbl_max = 511;
	tbl->tbl_items = 0;
	Newz(0, tbl->tbl_ary, tbl->tbl_max + 1, PTR_TBL_ENT_t*);
	return tbl;
}

/* map an existing pointer using a table */

static void *
ptr_table_fetch(PTR_TBL_t *tbl, void *sv)
{
	PTR_TBL_ENT_t *tblent;
	UV hash = PTR_TABLE_HASH(sv);
	tblent = tbl->tbl_ary[hash & tbl->tbl_max];
	for (; tblent; tblent = tblent->next) {
		if (tblent->oldval == sv) {
			CLONE_DEBUG("    found value in ptr_table: 0x%x => 0x%x\n", sv, tblent->newval);
			return tblent->newval;
		}
	}
	return (void*)NULL;
}

/* add a new entry to a pointer-mapping table */

static void
ptr_table_store(PTR_TBL_t *tbl, void *oldv, void *newv)
{
	PTR_TBL_ENT_t *tblent, **otblent;
	/* XXX this may be pessimal on platforms where pointers aren't good
	 * hash values e.g. if they grow faster in the most significant
	 * bits */
	UV hash = PTR_TABLE_HASH(oldv);
	bool empty = 1;
	CLONE_DEBUG("    storing value in ptr_table: 0x%x => 0x%x\n", oldv, newv);

	otblent = &tbl->tbl_ary[hash & tbl->tbl_max];
	for (tblent = *otblent; tblent; empty=0, tblent = tblent->next) {
		if (tblent->oldval == oldv) {
			tblent->newval = newv;
			return;
		}
	}
	Newz(0, tblent, 1, PTR_TBL_ENT_t);
	tblent->oldval = oldv;
	tblent->newval = newv;
	tblent->next = *otblent;
	*otblent = tblent;
	tbl->tbl_items++;
	if (!empty && tbl->tbl_items > tbl->tbl_max)
		ptr_table_grow(tbl);
}

/* double the hash bucket size of an existing ptr table */

static void
ptr_table_grow(PTR_TBL_t *tbl)
{
	PTR_TBL_ENT_t **ary = tbl->tbl_ary;
	UV oldsize = tbl->tbl_max + 1;
	UV newsize = oldsize * 2;
	UV i;

	Renew(ary, newsize, PTR_TBL_ENT_t*);
	Zero(&ary[oldsize], newsize-oldsize, PTR_TBL_ENT_t*);
	tbl->tbl_max = --newsize;
	tbl->tbl_ary = ary;
	for (i=0; i < oldsize; i++, ary++) {
		PTR_TBL_ENT_t **curentp, **entp, *ent;
		if (!*ary)
			continue;
		curentp = ary + oldsize;
		for (entp = ary, ent = *ary; ent; ent = *entp) {
			if ((newsize & PTR_TABLE_HASH(ent->oldval)) != i) {
				*entp = ent->next;
				ent->next = *curentp;
				*curentp = ent;
				continue;
			}
			else
				entp = &ent->next;
		}
	}
}

/* remove all the entries from a ptr table */

static void
ptr_table_clear(PTR_TBL_t *tbl)
{
	register PTR_TBL_ENT_t **array;
	register PTR_TBL_ENT_t *entry;
	register PTR_TBL_ENT_t *oentry = Null(PTR_TBL_ENT_t*);
	UV riter = 0;
	UV max;

	if (!tbl || !tbl->tbl_items) {
		return;
	}

	array = tbl->tbl_ary;
	entry = array[0];
	max = tbl->tbl_max;

	for (;;) {
		if (entry) {
			oentry = entry;
			entry = entry->next;
			Safefree(oentry);
		}
		if (!entry) {
			if (++riter > max) {
				break;
			}
			entry = array[riter];
		}
	}

	tbl->tbl_items = 0;
}

/* clear and free a ptr table */

static void
ptr_table_free(PTR_TBL_t *tbl)
{
	if (!tbl) {
		return;
	}
	ptr_table_clear(tbl);
	Safefree(tbl->tbl_ary);
	Safefree(tbl);
}

/* Duplicate a regexp. Required reading: pregcomp() and pregfree() in
   regcomp.c. AMS 20010712 */

static REGEXP *
clone_re(REGEXP *r, PTR_TBL_t *ptr_table)
{
	REGEXP *ret;
	int i, len, npar;
	struct reg_substr_datum *s;

	CLONE_DEBUG("inside clone_re\n");
	if (!r)
		return (REGEXP *)NULL;

	if ((ret = (REGEXP *)ptr_table_fetch(ptr_table, r)))
		return ret;

	len = r->offsets[0];
	npar = r->nparens+1;

	Newc(0, ret, sizeof(regexp) + (len+1)*sizeof(regnode), char, regexp);
	Copy(r->program, ret->program, len+1, regnode);

	New(0, ret->startp, npar, I32);
	Copy(r->startp, ret->startp, npar, I32);
	New(0, ret->endp, npar, I32);
	Copy(r->startp, ret->startp, npar, I32);

	New(0, ret->substrs, 1, struct reg_substr_data);
	for (s = ret->substrs->data, i = 0; i < 3; i++, s++) {
		s->min_offset = r->substrs->data[i].min_offset;
		s->max_offset = r->substrs->data[i].max_offset;
		s->substr = clone_sv_inc(r->substrs->data[i].substr, ptr_table);
		s->utf8_substr = clone_sv_inc(r->substrs->data[i].utf8_substr, ptr_table);
	}

	ret->regstclass = NULL;
	if (r->data) {
		struct reg_data *d;
		int count = r->data->count;

		Newc(0, d, sizeof(struct reg_data) + count*sizeof(void *),
				char, struct reg_data);
		New(0, d->what, count, U8);

		d->count = count;
		for (i = 0; i < count; i++) {
			d->what[i] = r->data->what[i];
			switch (d->what[i]) {
				case 's':
					d->data[i] = clone_sv_inc((SV *)r->data->data[i], ptr_table);
					break;
				case 'p':
					d->data[i] = clone_av_inc((AV *)r->data->data[i], ptr_table);
					break;
				case 'f':
					/* This is cheating. */
					New(0, d->data[i], 1, struct regnode_charclass_class);
					StructCopy(r->data->data[i], d->data[i], struct regnode_charclass_class);
					ret->regstclass = (regnode*)d->data[i];
					break;
				case 'o':
					/* Compiled op trees are readonly, and can thus be
					   shared without duplication. */
					d->data[i] = (void*)OpREFCNT_inc((OP*)r->data->data[i]);
					break;
				case 'n':
					d->data[i] = r->data->data[i];
					break;
			}
		}

		ret->data = d;
	}
	else
		ret->data = NULL;

	New(0, ret->offsets, 2*len+1, U32);
	Copy(r->offsets, ret->offsets, 2*len+1, U32);

	ret->precomp        = SAVEPVN(r->precomp, r->prelen);
	ret->refcnt         = r->refcnt;
	ret->minlen         = r->minlen;
	ret->prelen         = r->prelen;
	ret->nparens        = r->nparens;
	ret->lastparen      = r->lastparen;
	ret->lastcloseparen = r->lastcloseparen;
	ret->reganch        = r->reganch;

	ret->sublen         = r->sublen;

	if (RX_MATCH_COPIED(ret))
		ret->subbeg  = SAVEPVN(r->subbeg, r->sublen);
	else
		ret->subbeg = Nullch;

	ptr_table_store(ptr_table, r, ret);
	return ret;
}

/* duplicate a chain of magic */

static MAGIC *
clone_mg(MAGIC *mg, PTR_TBL_t *ptr_table)
{
	MAGIC *mgprev = (MAGIC*)NULL;
	MAGIC *mgret;

	CLONE_DEBUG("inside clone_mg\n");

	if (!mg)
		return (MAGIC*)NULL;

	/* look for it in the table first */
	mgret = (MAGIC*)ptr_table_fetch(ptr_table, mg);

	if (mgret)
		return mgret;

	for (; mg; mg = mg->mg_moremagic) {
		MAGIC *nmg;
		Newz(0, nmg, 1, MAGIC);

		if (mgprev) {
			mgprev->mg_moremagic = nmg;
		} else {
			mgret = nmg;
		}

		nmg->mg_virtual	= mg->mg_virtual; /* XXX copy dynamic vtable? */
		nmg->mg_private	= mg->mg_private;
		nmg->mg_type	= mg->mg_type;
		nmg->mg_flags	= mg->mg_flags;

		if (mg->mg_type == PERL_MAGIC_qr) {
			nmg->mg_obj	= (SV*)clone_re((REGEXP*)mg->mg_obj, ptr_table);
		} else if (mg->mg_type == WEAKREF_IDENTIFIER) {
			AV *av = (AV*) mg->mg_obj;
			SV **svp;
			I32 i;
			SvREFCNT_inc(nmg->mg_obj = (SV*)newAV());
			svp = AvARRAY(av);
			for (i = AvFILLp(av); i >= 0; --i) {
				if (!svp[i]) continue;
				av_push((AV*)nmg->mg_obj,clone_sv(svp[i], ptr_table));
			}
		} else {
			nmg->mg_obj	= (mg->mg_flags & MGf_REFCOUNTED)
				? clone_sv_inc(mg->mg_obj, ptr_table)
				: clone_sv(mg->mg_obj, ptr_table);
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
						namtp->table[i] = clone_cv_inc(amtp->table[i], ptr_table);
					}
				}
			} else if (mg->mg_len == HEf_SVKEY) {
				nmg->mg_ptr	= (char*)clone_sv_inc((SV*)mg->mg_ptr, ptr_table);
			}
		}

/* FIXME - only for threaded perls */
=pod
		if ((mg->mg_flags & MGf_DUP) && mg->mg_virtual && mg->mg_virtual->svt_dup) {
			Perl_croak("can't handle clone hook");
			CALL_FPTR(nmg->mg_virtual->svt_dup)(nmg, 0); /* FIXME missing CLONE_PARAMS *param */
		}
=cut

		mgprev = nmg;
	}
	return mgret;
}

static void
clone_rvpv(SV *sstr, SV *dstr, PTR_TBL_t *ptr_table)
{
	CLONE_DEBUG("inside clone_rvpv\n");
	if (SvROK(sstr)) {
		SvRV(dstr) = SvWEAKREF(sstr) ? clone_sv(SvRV(sstr), ptr_table) : clone_sv_inc(SvRV(sstr), ptr_table);
	} else if (SvPVX(sstr)) {
		/* Has something there */
		if (SvLEN(sstr)) {
			/* Normal PV - clone whole allocated space */
			SvPVX(dstr) = SAVEPVN(SvPVX(sstr), SvLEN(sstr)-1);
		} else {
			/* Special case - not normally malloced for some reason */
			if (SvREADONLY(sstr) && SvFAKE(sstr)) {
				/* A "shared" PV */
				SvPVX(dstr) = CLONE_SHAREPVN(SvPVX(sstr), SvCUR(sstr), SvUVX(sstr));
				SvUVX(dstr) = SvUVX(sstr);
			} else {
				/* Some other special case - random pointer */
				SvPVX(dstr) = SvPVX(sstr);
			}
		}
	} else {
		/* Copy the Null */
		SvPVX(dstr) = SvPVX(sstr);
	}
}

/* duplicate an SV of any type (including AV, HV etc) */

static SV *
clone_sv(SV *sstr, PTR_TBL_t *ptr_table)
{
	SV * dstr;

	CLONE_DEBUG("inside clone_sv\n");
	if (!sstr || SvTYPE(sstr) == SVTYPEMASK)
		return Nullsv;

	/* look for it in the table first */
	dstr = (SV*)ptr_table_fetch(ptr_table, sstr);

	if (dstr)
		return dstr;

	switch (SvTYPE(sstr)) {
		case SVt_NULL:
			CLONE_DEBUG("    detected type: %s (NULL)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			break;
		case SVt_IV:
			CLONE_DEBUG("    detected type: %s (IV)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			SvIVX(dstr) = SvIVX(sstr);
			break;
		case SVt_NV:
			CLONE_DEBUG("    detected type: %s (NV)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			SvNVX(dstr) = SvNVX(sstr);
			break;
		case SVt_RV:
			CLONE_DEBUG("    detected type: %s (RV)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			clone_rvpv(sstr, dstr, ptr_table);
			break;
		case SVt_PV:
			CLONE_DEBUG("    detected type: %s (PV)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			SvCUR(dstr)     = SvCUR(sstr);
			SvLEN(dstr)     = SvLEN(sstr);
			clone_rvpv(sstr, dstr, ptr_table);
			break;
		case SVt_PVIV:
			CLONE_DEBUG("    detected type: %s (PVIV)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			SvCUR(dstr)	= SvCUR(sstr);
			SvLEN(dstr)	= SvLEN(sstr);
			SvIVX(dstr)	= SvIVX(sstr);
			clone_rvpv(sstr, dstr, ptr_table);
			break;
		case SVt_PVNV:
			CLONE_DEBUG("    detected type: %s (PVNV)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			SvCUR(dstr)	= SvCUR(sstr);
			SvLEN(dstr)	= SvLEN(sstr);
			SvIVX(dstr)	= SvIVX(sstr);
			SvNVX(dstr)	= SvNVX(sstr);
			clone_rvpv(sstr, dstr, ptr_table);
			break;
		case SVt_PVMG:
			CLONE_DEBUG("    detected type: %s (PVMG)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			SvCUR(dstr)	= SvCUR(sstr);
			SvLEN(dstr)	= SvLEN(sstr);
			SvIVX(dstr)	= SvIVX(sstr);
			SvNVX(dstr)	= SvNVX(sstr);
			SvMAGIC(dstr) = clone_mg(SvMAGIC(sstr), ptr_table);
			CLONE_COPY_STASH(sstr, dstr);
			clone_rvpv(sstr, dstr, ptr_table);
			break;
		case SVt_PVBM:
			CLONE_DEBUG("    detected type: %s (PVBM)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			SvCUR(dstr)	= SvCUR(sstr);
			SvLEN(dstr)	= SvLEN(sstr);
			SvIVX(dstr)	= SvIVX(sstr);
			SvNVX(dstr)	= SvNVX(sstr);
			SvMAGIC(dstr) = clone_mg(SvMAGIC(sstr), ptr_table);
			CLONE_COPY_STASH(sstr, dstr);
			clone_rvpv(sstr, dstr, ptr_table);
			BmRARE(dstr) = BmRARE(sstr);
			BmUSEFUL(dstr) = BmUSEFUL(sstr);
			BmPREVIOUS(dstr) = BmPREVIOUS(sstr);
			break;
		case SVt_PVLV:
			CLONE_DEBUG("    detected type: %s (PVLV)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			SvCUR(dstr) = SvCUR(sstr);
			SvLEN(dstr) = SvLEN(sstr);
			SvIVX(dstr) = SvIVX(sstr);
			SvNVX(dstr) = SvNVX(sstr);
			SvMAGIC(dstr) = clone_mg(SvMAGIC(sstr), ptr_table);
			CLONE_COPY_STASH(sstr, dstr);
			clone_rvpv(sstr, dstr, ptr_table);
			LvTARGOFF(dstr) = LvTARGOFF(sstr); /* XXX sometimes holds PMOP* when DEBUGGING */
			LvTARGLEN(dstr) = LvTARGLEN(sstr);
			if (LvTYPE(sstr) == 't') { /* for tie: unrefcnted fake (SV**) */
				LvTARG(dstr) = dstr;
			} else if (LvTYPE(sstr) == 'T') { /* for tie: fake HE */
				LvTARG(dstr) = (SV*)clone_he((HE*)LvTARG(sstr), 0, ptr_table);
			} else {
				LvTARG(dstr) = clone_sv_inc(LvTARG(sstr), ptr_table);
			}
			LvTYPE(dstr) = LvTYPE(sstr);
			break;
		case SVt_PVGV:
			CLONE_DEBUG("    detected type: %s (PVGV)\n", sv_reftype(sstr, 0));
			CLONE_PASS_THRU(sstr, dstr, ptr_table);
			break;
		case SVt_PVIO:
			CLONE_DEBUG("    detected type: %s (PVIO)\n", sv_reftype(sstr, 0));
			CLONE_PASS_THRU(sstr, dstr, ptr_table);
			break;
		case SVt_PVAV:
			CLONE_DEBUG("    detected type: %s (PVAV)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			SvCUR(dstr)	= SvCUR(sstr);
			SvLEN(dstr)	= SvLEN(sstr);
			SvIVX(dstr)	= SvIVX(sstr);
			SvNVX(dstr)	= SvNVX(sstr);
			SvMAGIC(dstr) = clone_mg(SvMAGIC(sstr), ptr_table);
			CLONE_COPY_STASH(sstr, dstr);
			AvARYLEN((AV*)dstr) = clone_sv_inc(AvARYLEN((AV*)sstr), ptr_table);
			AvFLAGS((AV*)dstr) = AvFLAGS((AV*)sstr);

			if (AvARRAY((AV*)sstr)) {
				SV **dst_ary, **src_ary;
				SSize_t items = AvFILLp((AV*)sstr) + 1;

				src_ary = AvARRAY((AV*)sstr);
				Newz(0, dst_ary, AvMAX((AV*)sstr)+1, SV*);
				ptr_table_store(ptr_table, src_ary, dst_ary);
				SvPVX(dstr) = (char*)dst_ary;
				AvALLOC((AV*)dstr) = dst_ary;
				if (AvREAL((AV*)sstr)) {
					while (items-- > 0)
						*dst_ary++ = clone_sv_inc(*src_ary++, ptr_table);
				} else {
					while (items-- > 0)
						*dst_ary++ = clone_sv(*src_ary++, ptr_table);
				}
				items = AvMAX((AV*)sstr) - AvFILLp((AV*)sstr);
				while (items-- > 0) {
					*dst_ary++ = &PL_sv_undef;
				}
			} else {
				SvPVX(dstr)		= Nullch;
				AvALLOC((AV*)dstr)	= (SV**)NULL;
			}
			break;
		case SVt_PVHV:
			CLONE_DEBUG("    detected type: %s (PVHV)\n", sv_reftype(sstr, 0));
			CLONE_NEW_SV(sstr, dstr, ptr_table);
			SvCUR(dstr) = SvCUR(sstr);
			SvLEN(dstr) = SvLEN(sstr);
			SvIVX(dstr) = SvIVX(sstr);
			SvNVX(dstr) = SvNVX(sstr);
			SvMAGIC(dstr) = clone_mg(SvMAGIC(sstr), ptr_table);
			CLONE_COPY_STASH(sstr, dstr);
			HvRITER((HV*)dstr) = HvRITER((HV*)sstr);
			if (HvARRAY((HV*)sstr)) {
				STRLEN i = 0;
				XPVHV *dxhv = (XPVHV*)SvANY(dstr);
				XPVHV *sxhv = (XPVHV*)SvANY(sstr);
				Newz(0, dxhv->xhv_array, PERL_HV_ARRAY_ALLOC_BYTES(dxhv->xhv_max+1), char);

				while (i <= sxhv->xhv_max) {
					((HE**)dxhv->xhv_array)[i] = clone_he(((HE**)sxhv->xhv_array)[i], (bool)!!HvSHAREKEYS(sstr), ptr_table);
					++i;
				}

				dxhv->xhv_eiter = clone_he(sxhv->xhv_eiter, (bool)!!HvSHAREKEYS(sstr), ptr_table);
			}
			
			/* set by sv_upgrade
			else {
				SvPVX(dstr) = Nullch; 
				HvEITER((HV*)dstr) = (HE*)NULL;
			}
			*/
			HvPMROOT((HV*)dstr) = HvPMROOT((HV*)sstr); /* XXX */
			HvNAME((HV*)dstr) = SAVEPV(HvNAME((HV*)sstr));
			/* Record stashes for possible cloning in Perl_clone(). */
			/* if(HvNAME((HV*)dstr))
				av_push(param->stashes, dstr);
			*/
			break;
		case SVt_PVFM:
			CLONE_DEBUG("    detected type: %s (PVFM)\n", sv_reftype(sstr, 0));
		case SVt_PVCV:
			CLONE_DEBUG("    detected type: %s (PVCV)\n", sv_reftype(sstr, 0));
			CLONE_PASS_THRU(sstr, dstr, ptr_table);
			break;
		default:
			Perl_croak("Bizarre SvTYPE [%" IVdf "]", (IV)SvTYPE(sstr));
			break;
	}

	if (SvOBJECT(dstr) && SvTYPE(dstr) != SVt_PVIO)
		++PL_sv_objcount;

	return dstr;
}

MODULE = Scalar::Util::Clone		PACKAGE = Scalar::Util::Clone

PROTOTYPES: ENABLE

void
clone(original)
    SV *original
    PROTOTYPE: $
    PREINIT:
    SV *clone = &PL_sv_undef;
    PTR_TBL_t *ptr_table = NULL;
    PPCODE:

	CLONE_DEBUG("\n");
    ptr_table = ptr_table_new(); 
    clone = clone_sv(original, ptr_table);
    ptr_table_free(ptr_table);
    ptr_table = NULL;

    EXTEND(SP,1);
    /* PUSHs(sv_2mortal(SvREFCNT_inc(clone))); */
    PUSHs(clone);

void
supports_weakrefs()
    PROTOTYPE:
    CODE:
#ifdef SvWEAKREF
    XSRETURN(1);
#else
    XSRETURN(0);
#endif
