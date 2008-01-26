use 5.008007;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Net::Oping',
    VERSION_FROM      => 'lib/Net/Oping.pm',
    PREREQ_PM         => {},
    ($] >= 5.005
     ? (ABSTRACT_FROM => 'lib/Net/Oping.pm',
        AUTHOR        => 'Florian Forster <octo@verplant.org>')
     : ()),
    LIBS              => ['-loping', '-L/opt/oping/lib/ -loping'],
    DEFINE            => '',
    INC               => '-I/opt/oping/include/'
);
