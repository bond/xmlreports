#
# spec file for package xmlreports (Version 0.01)
#
Name:           xmlreports
License:        LGPL
Group:          Productivity/Networking/Web/Utilities
Provides:       xmlreports
Obsoletes:      xmlreports
Autoreqprov:    on
Version:        0.0.1
Release:        0
URL:            http://www.nsn.no
Summary:        A Web Server Log File Analysis Program
Source:         %{name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
XMLReports is a fork of webalizer that outputs XML-files instead of HTML files.
This makes them easy to style/transform with XSLT to formats for email and web.

Authors:
--------
    Anders Nor Berle <debolaz@gmail.com>
    Bradford L. Barrett <brad@usagl.net>
    Daniel Bond <db@nsn.no>

%debug_package
%prep
%setup -q -n %{name}-%{version}

%build
%configure

%install
rm -rf $RPM_BUILD_ROOT
make "DESTDIR=$RPM_BUILD_ROOT" install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_bindir}/%{name}

%changelog -n xmlreports
* Thu Sep 23 2008 - db@nsn.no
- Created initial SPEC-file

