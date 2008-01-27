use 5.006;
use ExtUtils::MakeMaker;

my @OPING_PREFIX = (qw(/opt/oping /usr /usr/local));
my $OPING_PREFIX;

for (my $i = 0; $i < @ARGV; $i++)
{
	if ($ARGV[$i] =~ m#^OPING_PREFIX=(.*[^/])#)
	{
		unshift (@OPING_PREFIX, $1);
		splice (@ARGV, $i, 1);
		$i--;
	}
}

for (my $i = 0; $i < @OPING_PREFIX; $i++)
{
	if (!-e $OPING_PREFIX[$i] . '/include/oping.h')
	{
		next;
	}

	$OPING_PREFIX = $OPING_PREFIX[$i];
	print "Found <oping.h> in $OPING_PREFIX/include\n";
	last;
}

if (!$OPING_PREFIX)
{
	my $search_path = join (', ', @OPING_PREFIX);
	print STDERR <<EOF;
******************************************************************************
* ERROR: COULD NOT FIND THE NEEDED HEADER FILE <oping.h>!                    *
******************************************************************************
The <oping.h> header file could not be found in the usual places. The prefix
paths searched right now are:
  $search_path

Please rerun Makefile.PL giving the prefix to the oping library using the
`OPING_PREFIX' argument. If you, for example, had installed the oping library
to /tmp/oping, the header file would be at /tmp/oping/include/oping.h; you'd
then need to run the Makefile.PL as follows:
  perl Makefile.PL OPING_PREFIX=/tmp/oping

As you can see, the argument passed via `OPING_PREFIX' must be the same
directory you passed to the liboping configure script using the `--prefix'
argument.

No Makefile has been created.
EOF
	exit (0);
}

WriteMakefile(
    NAME              => 'Net::Oping',
    VERSION_FROM      => 'lib/Net/Oping.pm',
    PREREQ_PM         => {},
    ($] >= 5.005
     ? (ABSTRACT_FROM => 'lib/Net/Oping.pm',
        AUTHOR        => 'Florian Forster <octo@verplant.org>')
     : ()),
    LIBS              => ["-L$OPING_PREFIX/lib -loping"],
    DEFINE            => '',
    INC               => "-I$OPING_PREFIX/include"
);
