#!/bin/bash

if [ -z "$1" ]; then
  cat <<EOF
usage:
  ./make_spec.sh PACKAGE [BRANCH]
EOF
  exit 1
fi

cd $(dirname $0)

YEAR=$(date +%Y)
VERSION=$(cat ../../VERSION)
REVISION=$(git rev-list HEAD | wc -l)
COMMIT=$(git rev-parse --short HEAD)
COMMIT_UNIX_TIME=$(git show -s --format=%ct)
VERSION="${VERSION%+*}+$(date -d @$COMMIT_UNIX_TIME +%Y%m%d).git_r${REVISION}_${COMMIT}"
NAME=$1
BRANCH=${2:-master}
SAFE_BRANCH=${BRANCH//\//-}

cat <<EOF > ${NAME}.spec
#
# spec file for package $NAME
#
# Copyright (c) $YEAR SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           $NAME
Version:        $VERSION
Release:        0
Summary:        CLI for interacting with SUSE CaaS Platform Clusters
License:        Apache-2.0
Group:          System/Management
Url:            https://github.com/kubic-project/caasp-cli
Source:         ${SAFE_BRANCH}.tar.gz
BuildRequires:  go >= 1.8.3
BuildRequires:  golang-packaging
BuildRequires:  golang(API) = 1.8
Requires(post): %fillup_prereq
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
%{go_nostrip}
%{go_provides}

%description
SUSE CaaS Platform CLI provides command-line tooling for managing a SUSE CaaS Platform cluster

%prep
%setup -q -n ${NAME}-${SAFE_BRANCH}

%build
%{goprep} github.com/kubic-project/caasp-cli
%{gobuild}

%install
%{goinstall}

%files
%defattr(-,root,root)
%doc README.md
%if 0%{?suse_version} < 1500
%doc LICENSE
%else
%license LICENSE
%endif
%{_bindir}/caasp-cli

%changelog
EOF
