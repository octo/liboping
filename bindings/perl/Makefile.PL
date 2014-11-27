use 5.006;
use ExtUtils::MakeMaker;
use Config (%Config);

my @OPING_PREFIX = (qw(/opt/oping /usr /usr/local));
my $OPING_PREFIX;

my $OPING_CPPFLAGS;
my $OPING_LDDLFLAGS;
my $OPING_LIBS;
my $OPING_DEPEND;

# TOP_BUILDDIR is set by liboping's build system, so Net::Oping can link with
# the yet uninstalled library.
my $TOP_BUILDDIR;
my $TARGET_LIBDIR;

# Parse custom command line arguments.
for (my $i = 0; $i < @ARGV; $i++)
{
	if ($ARGV[$i] =~ m#^OPING_PREFIX=(.*[^/])#)
	{
		unshift (@OPING_PREFIX, $1);
		splice (@ARGV, $i, 1);
		$i--;
	}
	elsif ($ARGV[$i] =~ m#^TOP_BUILDDIR=(.*[^/])#)
	{
		$TOP_BUILDDIR = $1;
		# TOP_BUILDDIR is passed from bindings/, but we're currently in
		# bindings/perl/. If it is a relative path, we need to add an
		# extra `../' in order to compensate for this.
		if ($TOP_BUILDDIR !~ m#^/#)
		{
			$TOP_BUILDDIR = "../$TOP_BUILDDIR";
		}
		splice (@ARGV, $i, 1);
		$i--;
	}
	elsif ($ARGV[$i] =~ m#^TARGET_LIBDIR=(.*[^/])#)
	{
		# Only save TARGET_LIBDIR if it's not a standard system library
		# directory, such as /usr/lib.
		if (!is_system_libdir ($1))
		{
			$TARGET_LIBDIR = $1;
		}
		splice (@ARGV, $i, 1);
		$i--;
	}
}

if (!$TOP_BUILDDIR)
{
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
}

if ($TOP_BUILDDIR)
{
	# Use LDDLFLAGS here instead of LIBS, because:
	#  1) We need to make sure our library path comes first (and no locally
	#     installed version is used).
	#  2) Prevent MakeMaker from stipping the -rpath option when the
	#     library is to be installed in a non-standard path. Standard-paths
	#     are read from $Config{'libsdirs'} above.
	$OPING_CPPFLAGS = "-I$TOP_BUILDDIR/src";
	$OPING_LDDLFLAGS = "-L$TOP_BUILDDIR/src/.libs " . $Config{'lddlflags'};
	$OPING_LIBS = "-L$TOP_BUILDDIR/src/.libs -loping";

	if ($TARGET_LIBDIR)
	{
		$OPING_LDDLFLAGS .= qq( -Wl,-rpath -Wl,"$TARGET_LIBDIR");
	}

	$OPING_DEPEND = { 'Oping.o' => "$TOP_BUILDDIR/src/liboping.la" };
}
elsif ($OPING_PREFIX)
{
	# -rpath is automagically set in this case.
	$OPING_CPPFLAGS = "-I$OPING_PREFIX/include";
	$OPING_LIBS = "-L$OPING_PREFIX/lib -loping";
}

if (!$OPING_CPPFLAGS)
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
        AUTHOR        => 'Florian Forster <ff@octo.it>')
     : ()),
    ($OPING_DEPEND ? (depend => $OPING_DEPEND) : ()),
    LIBS              => [$OPING_LIBS],
    ($OPING_LDDLFLAGS ? (LDDLFLAGS => "$OPING_LDDLFLAGS") : ()),
    DEFINE            => '',
    INC               => "$OPING_CPPFLAGS"
);

sub is_system_libdir
{
	my $path = shift;
	for (split (' ', $Config{'libsdirs'}))
	{
		if ($path eq $_)
		{
			return (1);
		}
	}
	return;
}
