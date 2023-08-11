#Global macro or variable
%global libpsl_version %(pkg-config --modversion libpsl 2>/dev/null || echo 0)
%global libssh_version %(pkg-config --modversion libssh 2>/dev/null || echo 0)
%global openssl_version %({ pkg-config --modversion openssl 2>/dev/null || echo 0;} | sed 's|-|-0.|')
%global _configure ../configure

Name:           curl
Version:        7.79.1
Release:        23
Summary:        Curl is used in command lines or scripts to transfer data
License:        MIT
URL:            https://curl.haxx.se/
Source:         https://curl.haxx.se/download/curl-%{version}.tar.xz

Patch1:         backport-0101-curl-7.32.0-multilib.patch
Patch2:         backport-CVE-2022-22576.patch
Patch3:         backport-CVE-2022-27775.patch
Patch4:         backport-CVE-2022-27776.patch
Patch5:         backport-pre-CVE-2022-27774.patch
Patch6:         backport-001-CVE-2022-27774.patch
Patch7:         backport-002-CVE-2022-27774.patch
Patch8:         backport-CVE-2022-27781.patch
Patch9:         backport-pre-CVE-2022-27782.patch
Patch10:        backport-CVE-2022-27782.patch
Patch11:        backport-CVE-2022-32205.patch
Patch12:        backport-CVE-2022-32206.patch
Patch13:        backport-CVE-2022-32207.patch
Patch14:        backport-CVE-2022-32208.patch
Patch15:        backport-fix-configure-disable-http-auth-build-error.patch
Patch16:        backport-CVE-2022-35252-cookie-reject-cookies-with-control-bytes.patch
Patch17:        backport-CVE-2022-32221.patch
Patch18:        backport-CVE-2022-42916.patch
Patch20:        backport-CVE-2022-43551-http-use-the-IDN-decoded-name-in-HSTS-checks.patch
Patch21:        backport-CVE-2022-43552-smb-telnet-do-not-free-the-protocol-struct-in-_done.patch
Patch22:        backport-0001-CVE-2023-23914-CVE-2023-23915.patch
Patch23:        backport-0002-CVE-2023-23914-CVE-2023-23915.patch
Patch24:        backport-0003-CVE-2023-23914-CVE-2023-23915.patch
Patch25:        backport-0004-CVE-2023-23914-CVE-2023-23915.patch
Patch26:        backport-0005-CVE-2023-23914-CVE-2023-23915.patch
Patch27:        backport-0001-CVE-2023-23916.patch
Patch28:        backport-0002-CVE-2023-23916.patch
Patch29:        backport-CVE-2023-27533.patch
Patch30:        backport-CVE-2023-27534-pre1.patch
Patch31:        backport-CVE-2023-27534.patch
Patch32:        backport-CVE-2023-27538.patch
Patch33:        backport-CVE-2023-27535-pre1.patch
Patch34:        backport-CVE-2023-27536.patch
Patch35:        backport-CVE-2023-27535.patch
Patch36:        backport-after-CVE-2022-32207-to-fix-build-error-when-user-don-t-use-glibc.patch
Patch37:        backport-CVE-2023-28321.patch 
Patch38:        backport-CVE-2023-28322.patch
Patch39:        backport-0001-CVE-2023-28320.patch
Patch40:        backport-0002-CVE-2023-28320.patch
Patch41:        backport-0003-CVE-2023-28320.patch
Patch42:        backport-curl-tool-erase-some-more-sensitive-command-line-arg.patch
Patch43:        backport-tool_getparam-repair-cleanarg.patch
Patch44:        backport-tool_getparam-fix-cleanarg-for-unicode-builds.patch
Patch45:        backport-getparam-correctly-clean-args.patch
Patch46:        backport-tool_getparam-fix-hiding-of-command-line-secrets.patch
Patch47:        backport-multi-shut-down-CONNECT-in-Curl_detach_connnection.patch
Patch48:        backport-curl_easy_cleanup.3-remove-from-multi-handle-first.patch
Patch49:        backport-http_proxy-make-Curl_connect_done-work-for-proxy-dis.patch
Patch50:        backport-Curl_connect_done-handle-being-called-twice.patch
Patch51:        backport-tftp-mark-protocol-as-not-possible-to-do-over-CONNEC.patch
Patch52:        backport-test1939-require-proxy-support-to-run.patch
Patch53:        backport-lib1939-make-it-endure-torture-tests.patch
Patch54:        backport-CVE-2022-42915.patch
Patch55:        backport-tests-verify-the-fix-for-CVE-2022-27774.patch
Patch56:        backport-test442-443-test-cookie-caps.patch
Patch57:        backport-test444-test-many-received-Set-Cookie.patch
Patch58:        backport-test8-verify-that-ctrl-byte-cookies-are-ignored.patch
Patch59:        backport-test1948-verify-PUT-POST-reusing-the-same-handle.patch
Patch60:        backport-test387-verify-rejection-of-compression-chain-attack.patch
Patch61:        backport-hostcheck-fix-host-name-wildcard-checking.patch
Patch62:        backport-CVE-2023-32001.patch

BuildRequires:  automake brotli-devel coreutils gcc groff krb5-devel
BuildRequires:  libidn2-devel libnghttp2-devel libpsl-devel
BuildRequires:  libssh-devel make openldap-devel openssh-clients openssh-server
BuildRequires:  openssl-devel perl-interpreter pkgconfig python3-devel sed
BuildRequires:  stunnel zlib-devel gnutls-utils nghttp2 perl(IO::Compress::Gzip)
BuildRequires:  perl(Getopt::Long) perl(Pod::Usage) perl(strict) perl(warnings)
BuildRequires:  perl(Cwd) perl(Digest::MD5) perl(Exporter) perl(File::Basename)
BuildRequires:  perl(File::Copy) perl(File::Spec) perl(IPC::Open2) perl(MIME::Base64)
BuildRequires:  perl(Time::Local) perl(Time::HiRes) perl(vars)

Requires:       libcurl = %{version}-%{release}
Provides:       curl-full = %{version}-%{release} webclient

%description
cURL is a computer software project providing a library (libcurl) and
command-line tool (curl) for transferring data using various protocols.

%package -n 	libcurl
Summary:	A library for getting files from web servers
Requires:	libssh >= %{libssh_version} libpsl >= %{libpsl_version}
Requires:       openssl-libs >= 1:%{openssl_version}
Provides:	libcurl-full = %{version}-%{release} 
Conflicts:	curl < 7.66.0-3

%description -n libcurl
A library for getting files from web servers.

%package -n 	libcurl-devel
Summary:	Header files for libcurl
Requires:	libcurl = %{version}-%{release}
Provides:	curl-devel = %{version}-%{release}
Obsoletes:	curl-devel < %{version}-%{release}
	
%description -n libcurl-devel
Header files for libcurl.

%package_help

%prep
%autosetup -n %{name}-%{version} -p1

printf "1112\n1455\n1184\n1801\n1592\n" >> tests/data/DISABLED

# adapt test 323 for updated OpenSSL
sed -e 's/^35$/35,52/' -i tests/data/test323
# use localhost6 instead of ip6-localhost in the curl test-suite
(
    # avoid glob expansion in the trace output of `bash -x`
    { set +x; } 2>/dev/null
    cmd="sed -e 's|ip6-localhost|localhost6|' -i tests/data/test[0-9]*"
    printf "+ %s\n" "$cmd" >&2
    eval "$cmd"
)

%build
# regenerate Makefile.in files
aclocal -I m4
automake

install -d build-full
export common_configure_opts="--cache-file=../config.cache \
    --enable-symbol-hiding  --enable-ipv6  --enable-threaded-resolver \
    --with-gssapi  --with-nghttp2  --with-ssl \
    --with-ca-bundle=%{_sysconfdir}/pki/tls/certs/ca-bundle.crt"

%global _configure ../configure

# configure full build
(
    cd build-full
    %configure $common_configure_opts \
        --enable-ldap \
        --enable-ldaps \
        --enable-manual \
        --with-brotli \
        --with-libidn2 \
        --with-libpsl \
        --with-libssh
)

sed -e 's/^runpath_var=.*/runpath_var=/' \
    -e 's/^hardcode_libdir_flag_spec=".*"$/hardcode_libdir_flag_spec=""/' \
    -i build-full/libtool

%make_build V=1 -C build-full

%check
# compile upstream test-cases
%make_build V=1 -C build-full/tests
 
# relax crypto policy for the test-suite to make it pass again (#1610888)
export OPENSSL_SYSTEM_CIPHERS_OVERRIDE=XXX
export OPENSSL_CONF=
 
# make runtests.pl work for out-of-tree builds
export srcdir=../../tests
 
# prevent valgrind from being extremely slow (#1662656)
unset DEBUGINFOD_URLS
 
# run the upstream test-suite for curl-full
for size in full; do (
    cd build-${size}
 
    # we have to override LD_LIBRARY_PATH because we eliminated rpath
    export LD_LIBRARY_PATH="${PWD}/lib/.libs"
 
    cd tests
    perl -I../../tests ../../tests/runtests.pl -a -n -p -v '!flaky'
)
done

%install
rm -f ${RPM_BUILD_ROOT}%{_libdir}/libcurl.{la,so}

# install libcurl.m4 for devel
install -D -m 644 docs/libcurl/libcurl.m4 $RPM_BUILD_ROOT%{_datadir}/aclocal/libcurl.m4

# curl file install
cd build-full
%make_install

# install zsh completion for curl
LD_LIBRARY_PATH="$RPM_BUILD_ROOT%{_libdir}:$LD_LIBRARY_PATH" %make_install -C scripts

# do not install /usr/share/fish/completions/curl.fish which is also installed
# by fish-3.0.2-1.module_f31+3716+57207597 and would trigger a conflict
rm -rf ${RPM_BUILD_ROOT}%{_datadir}/fish

rm -f ${RPM_BUILD_ROOT}%{_libdir}/libcurl.a
rm -rf ${RPM_BUILD_ROOT}%{_libdir}/libcurl.la

%ldconfig_scriptlets

%ldconfig_scriptlets -n libcurl

%files
%defattr(-,root,root)
%license COPYING
%{_bindir}/curl
%{_datadir}/zsh

%files -n libcurl
%defattr(-,root,root)
%{_libdir}/libcurl.so.4
%{_libdir}/libcurl.so.4.[0-9].[0-9]

%files -n libcurl-devel
%defattr(-,root,root)
%doc docs/examples/*.c docs/examples/Makefile.example docs/INTERNALS.md
%doc docs/CONTRIBUTE.md docs/libcurl/ABI.md
%{_bindir}/curl-config*
%{_includedir}/curl
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
%{_datadir}/aclocal/libcurl.m4

%files help
%defattr(-,root,root)
%doc CHANGES README*
%doc docs/BUGS.md docs/FAQ docs/FEATURES.md
%doc docs/TheArtOfHttpScripting.md docs/TODO
%{_mandir}/man1/curl.1*
%{_mandir}/man1/curl-config.1*
%{_mandir}/man3/*

%changelog
* Thu Jul 20 2023 zhouyihang <zhouyihang3@h-partners.com> - 7.79.1-23
- Type:CVE
- CVE:CVE-2023-32001
- SUG:NA
- DESC:fix CVE-2023-32001

* Mon Jul 10 2023 zhouyihang <zhouyihang3@h-partners.com> - 7.79.1-22
- Type:bugfix
- CVE:NA
- SUG:NA
- DESC:backport some testcases

* Mon Jul 03 2023 zhouyihang <zhouyihang3@h-partners.com> - 7.79.1-21
- Type:bugfix
- CVE:NA
- SUG:NA
- DESC:fix double-free when using https with tunneling proxy

* Mon Jun 19 2023 zhouyihang <zhouyihang3@h-partners.com> - 7.79.1-20
- Type:bugfix
- CVE:NA
- SUG:NA
- DESC:hide sensitive info in cmdline when ps

* Sat Jun 10 2023 zhouyihang <zhouyihang3@h-partners.com> - 7.79.1-19
- Type:bugfix
- CVE:NA
- SUG:NA
- DESC:disable valgrind in tests

* Thu Jun 08 2023 xingwei <xingwei14@h-partners.com> - 7.79.1-18
- Type:CVE
- CVE:CVE-2023-28320
- SUG:NA
- DESC:fix CVE-2023-28320

* Wed May 24 2023 xingwei <xingwei14@h-partners.com> - 7.79.1-17
- Type:CVE
- CVE:CVE-2023-28321,CVE-2023-28322
- SUG:NA
- DESC:fix CVE-2023-28321,CVE-2023-28322

* Wed Apr 19 2023 gaihuiying <eaglegai@163.com> - 7.79.1-16
- Type:bugfix
- CVE:NA
- SUG:NA
- DESC:backport to fix build error when user don't use glibc

* Wed Mar 22 2023 xingwei <xingwei14@h-partners.com> - 7.79.1-15
- Type:cves
- CVE:CVE-2023-27533 CVE-2023-27534 CVE-2023-27535 CVE-2023-27536 CVE-2023-27538
- SUG:NA
- DESC:fix CVE-2023-27533 CVE-2023-27534 CVE-2023-27535 CVE-2023-27536 CVE-2023-27538

* Sat Feb 18 2023 xinghe <xinghe2@h-partners.com> - 7.79.1-14
- Type:cves
- CVE:CVE-2023-23914 CVE-2023-23915 CVE-2023-23916
- SUG:NA
- DESC:fix CVE-2023-23914 CVE-2023-23915 CVE-2023-23916

* Thu Dec 22 2022 zhouyihang <zhouyihang3@h-partners.com> - 7.79.1-13
- Type:cves
- CVE:CVE-2022-43551 CVE-2022-43552
- SUG:NA
- DESC:fix CVE-2022-43551 CVE-2022-43552

* Thu Oct 27 2022 yanglu <yanglu72@h-partners.com> - 7.79.1-12
- Type:cves
- CVE:CVE-2022-32221 CVE-2022-42915 CVE-2022-42916
- SUG:NA
- DESC:fix CVE-2022-32221 CVE-2022-42915 CVE-2022-42916

* Tue Oct 11 2022 huangduirong <huangduirong@huawei.com> - 7.79.1-11
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:Move autoreconf to build

* Thu Sep 01 2022 zhouyihang <zhouyihang3@h-partners.com> - 7.79.1-10
- Type:cves
- CVE:CVE-2022-35252
- SUG:NA
- DESC:fix CVE-2022-35252

* Mon Jul 25 2022 gaihuiying <eaglegai@163.com> - 7.79.1-9
- Type:bugfix
- CVE:NA
- SUG:NA
- DESC:fix build error when add --disable-http-auth configure option

* Tue Jul 05 2022 gaihuiying <eaglegai@163.com> - 7.79.1-8
- Type:cves
- CVE:CVE-2022-32207
- SUG:NA
- DESC:fix CVE-2022-32207 better

* Wed Jun 29 2022 gaihuiying <eaglegai@163.com> - 7.79.1-7
- Type:cves
- CVE:CVE-2022-32205 CVE-2022-32206 CVE-2022-32207 CVE-2022-32208
- SUG:NA
- DESC:fix CVE-2022-32205 CVE-2022-32206 CVE-2022-32207 CVE-2022-32208

* Tue May 17 2022 gaihuiying <eaglegai@163.com> - 7.79.1-6
- Type:cves
- CVE:CVE-2022-27781 CVE-2022-27782
- SUG:NA
- DESC:fix CVE-2022-27781 CVE-2022-27782

* Fri May 06 2022 gaihuiying <eaglegai@163.com> - 7.79.1-5
- Type:cves
- CVE:CVE-2022-22576 CVE-2022-27774 CVE-2022-27775 CVE-2022-27776
- SUG:NA
- DESC:fix CVE-2022-22576 CVE-2022-27774 CVE-2022-27775 CVE-2022-27776

* Tue Feb 22 2022 gaoxingwang <gaoxingwang@huawei.com> - 7.79.1-4
- Type:bugfix
- CVE:NA
- SUG:NA
- DESC:fix dict and neg telnet server start fail in upstream testcase

* Mon Jan 24 2022 gaoxingwang <gaoxingwang@huawei.com> - 7.79.1-3
- Type:bugfix
- CVE:NA
- SUG:NA
- DESC:enable check in spec

* Thu Jan 20 2022 yanglu <yanglu72@huawei.com> - 7.79.1-2
- Type:bugfix
- CVE:NA
- SUG:NA
- DESC:delete useless patch

* Tue Dec 14 2021 yanglu <yanglu72@huawei.com> - 7.79.1-1
- Type:requirement
- CVE:NA
- SUG:NA
- DESC:update curl to 7.79.1

* Wed Sep 29 2021 yanglu <yanglu72@huawei.com> - 7.77.0-3
- Type:CVE
- CVE:CVE-2021-22945 CVE-2021-22946 CVE-2021-22947
- SUG:NA
- DESC:fix CVE-2021-22945 CVE-2021-22946CVE-2021-22947

* Fri Aug 13 2021 gaihuiying <gaihuiying1@huawei.com> - 7.77.0-2
- Type:CVE
- CVE:CVE-2021-22925 CVE-2021-22926
- SUG:NA
- DESC:fix CVE-2021-22925 CVE-2021-22926

* Thu Jul 8 2021 gaihuiying <gaihuiying1@huawei.com> - 7.77.0-1
- Type:requirement
- CVE:NA
- SUG:NA
- DESC:update curl to 7.77.0

* Tue Jun 8 2021 gaihuiying <gaihuiying1@huawei.com> - 7.71.1-9
- Type:CVE
- CVE:CVE-2021-22897 CVE-2021-22898
- SUG:NA
- DESC:fix CVE-2021-22897 CVE-2021-22898

* Tue Apr 20 2021 gaihuiying <gaihuiying1@huawei.com> - 7.71.1-8
- Type:CVE
- CVE:CVE-2021-22890
- SUG:NA
- DESC:fix CVE-2021-22890

* Thu Apr 8 2021 xieliuhua <xieliuhua@huawei.com> - 7.71.1-7
- Type:CVE
- CVE:CVE-2021-22876
- SUG:NA
- DESC:fix CVE-2021-22876

* Tue Jan 26 2021 wangxiaopeng <wangxiaopeng7@huawei.com> - 7.71.1-6
- Type:CVE
- CVE:CVE-2020-8285
- SUG:NA
- DESC:fix CVE-2020-8285

* Tue Jan 19 2021 xielh2000 <xielh2000@163.com> - 7.71.1-5
- Type:CVE
- CVE:CVE-2020-8286
- SUG:NA
- DESC:fix CVE-2020-8286

* Mon Jan 18 2021 xihaochen <xihaochen@huawei.com> - 7.71.1-4
- Type:CVE
- CVE:CVE-2020-8284
- SUG:NA
- DESC:fix CVE-2020-8284

* Tue Jan 5 2021 gaihuiying <gaihuiying1@huawei.com> - 7.71.1-3
- Type:bugfix
- ID:NA
- SUG:NA
- DESC:fix downgrade error

* Mon Dec 28 2020 liuxin <liuxin264@huawei.com> - 7.71.1-2
- Type:cves
- ID:CVE-2020-8231
- SUG:NA
- DESC:fix CVE-2020-8231

* Fri Jul 24 2020 zhujunhao <zhujunhao8@huawei.com> - 7.71.1-1
- Update to 7.71.1

* Thu Apr 9 2020 songnannan <songnannan2@huawei.com> - 7.66.0-3
- split out the libcurl and libcurl-devel package 

* Tue Mar 17 2020 chenzhen <chenzhen44@huawei.com> - 7.66.0-2
- Type:cves
- ID:CVE-2019-15601
- SUG:NA
- DESC:fix CVE-2019-15601

* Sat Jan 11 2020 openEuler Buildteam <buildteam@openeuler.org> - 7.66.0-1
- update to 7.66.0

* Sat Dec 21 2019 openEuler Buildteam <buildteam@openeuler.org> - 7.61.1-4
- Type:cves
- ID:CVE-2019-5481 CVE-2019-5482
- SUG:NA
- DESC:fix CVE-2019-5481 CVE-2019-5482

* Wed Sep 18 2019 guanyanjie <guanyanjie@huawei.com> - 7.61.1-3
- Init for openEuler
