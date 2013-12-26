#
# SPEC file for liboping
#
# This SPEC file is provided as a starting point for your own package of
# liboping. It may use distribution specific commands or tags and may not be
# suited for your distribution in its verbatim form. If at all possible, please
# use a source-RPM (SRPM) provided by your distributor.
#
# That being said, bug reports concerning this SPEC file are welcome, of
# course. Please report any bugs you find to liboping's mailing list at
# <liboping at verplant.org>. Thanks to Benjamin Petrin for providing this
# file.  --octo
#
Name:           liboping
Version:        1.3.4 
Release:        1%{?dist}
Summary:        Ping library intended for use in network monitoring applications

Group:          System Environment/Libraries
License:        GPLv2
URL:            http://verplant.org/liboping/
Source0:        http://verplant.org/liboping/files/liboping-%{version}.tar.gz 
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

#TODO - find all build requirements using a clean system
#BuildRequires:         

%description
The %{name} package is a C library to generate ICMP echo requests, better known 
as “ping packets”. It is intended for use in network monitoring applications or
applications that would otherwise need to fork ping(1) frequently. It is like 
ping, ping6, and fping rolled into one.

%package        devel
Summary:        Development files for %{name}
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}

%description    devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%package        perl
Summary:        Perl bindings for %{name}
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}
Requires:       perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))

%description    perl
The %{name}-perl package contains a perl module for perl programs
that use %{name}.


%prep
%setup -q


%build
#Install perl bindings to vendor_perl instead of site_perl
%configure --disable-static --with-perl-bindings='INSTALLDIRS=vendor OPTIMIZE="%{optflags}"'
#The application uses a local copy of libtool, we need to remove rpath with the
#following two lines (see https://fedoraproject.org/wiki/Packaging/Guidelines#Beware_of_Rpath)
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
chmod -R u+w %{buildroot}/*
find %{buildroot} -name '*.la' -exec rm -f {} ';'
find %{buildroot} -type f -name .packlist -exec rm -f {} ';'
find %{buildroot} -type f -name '*.bs' -a -size 0 -exec rm -f {} ';'
find %{buildroot} -depth -type d -exec rmdir {} 2>/dev/null ';'
find %{buildroot} -type f -name perllocal.pod -exec rm -f {} ';'

%clean
rm -rf %{buildroot}


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING NEWS README ChangeLog
%{_libdir}/*.so.*
%{_bindir}/oping
%{_mandir}/man8/oping.8*


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/*.so
%{_mandir}/man3/liboping.3*
%{_mandir}/man3/ping_construct.3*
%{_mandir}/man3/ping_get_error.3*
%{_mandir}/man3/ping_host_add.3*
%{_mandir}/man3/ping_iterator_get.3*
%{_mandir}/man3/ping_iterator_get_context.3*
%{_mandir}/man3/ping_iterator_get_info.3*
%{_mandir}/man3/ping_send.3*
%{_mandir}/man3/ping_setopt.3*

%files perl
%defattr(-,root,root,-)
%doc bindings/perl/README bindings/perl/Changes
# For arch-specific packages: vendorarch
%{perl_vendorarch}/*
%exclude %dir %{perl_vendorarch}/auto/
%{_mandir}/man3/Net::Oping.3pm*


%changelog
* Fri Jan 22 2010 Benjamin Petrin <b.petrin@wpi.edu> - 1.3.4-1
- Initial package
