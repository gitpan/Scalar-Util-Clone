use 5.008;
use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
    'NAME'            =>    'Scalar::Util::Clone',
    'VERSION_FROM'    =>    'lib/Scalar/Util/Clone.pm',     # finds $VERSION
    'INSTALLDIRS'     =>    'site',
    'PREREQ_PM'       =>    { # e.g. Module::Name => 1.1
        'Tie::Hash'		=> 0,
        'IO::Handle'	=> 0,
        'Data::Dumper'	=> 0,
        'Test::More'	=> 0,
        'Scalar::Util'	=> 1.01, # for weaken(), isweak()
    },         
    'LIBS'            =>    [''],         # e.g. '-lm'
    # 'DEFINE'        =>    '',
    # 'OPTIMIZE'      =>    '-g3 -Wall',
    'OPTIMIZE'        =>    '-O3',
    'INC'             =>    ''         # e.g. '-I/usr/include/other'
);
