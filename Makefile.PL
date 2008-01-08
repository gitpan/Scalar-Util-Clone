use 5.008;
use ExtUtils::MakeMaker;

my $optimize = ($^O eq 'MSWin32') ? '-O2 -W4' : '-O3 -Wall';

WriteMakefile(
    'NAME'            =>    'Scalar::Util::Clone',
    'VERSION_FROM'    =>    'lib/Scalar/Util/Clone.pm', # finds $VERSION
    'PREREQ_PM'       =>    { # e.g. Module::Name => 1.1
        'Scalar::Util'    => 1.01, # for weaken(), isweak()
    },         
    'LIBS'            =>    [''], # e.g. '-lm'
    'OPTIMIZE'        =>    $optimize,
    # 'OPTIMIZE'        =>    '-g -Wall',
    'INC'             =>    '' # e.g. '-I/usr/include/other'
);
