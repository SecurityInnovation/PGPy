# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=6

PYTHON_COMPAT=( python{2_7,3_{3,4,5}} pypy )

inherit distutils-r1

if [[ "${PV}" == "0.4.0" ]]; then
	# PGPy 0.4.0's filename is slightly different because of difficulties with PyPI when uploading
	MY_PV="${PV}a"
fi

DESCRIPTION="Pretty Good Privacy for Python - a pure Python OpenPGP implementation."
HOMEPAGE="https://github.com/SecurityInnovation/PGPy/"
SRC_URI="mirror://pypi/P/PGPy/PGPy-${MY_PV-$PV}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""

RDEPEND="
		dev-python/singledispatch[${PYTHON_USEDEP}]
		dev-python/pyasn1[${PYTHON_USEDEP}]
		>=dev-python/six-1.9.0[${PYTHON_USEDEP}]
		>=dev-python/cryptography-1.1.0[${PYTHON_USEDEP}]
		$(python_gen_cond_dep 'dev-python/enum34[${PYTHON_USEDEP}]' python2_7 python3_3)"
DEPEND="${RDEPEND}
		dev-python/setuptools[${PYTHON_USEDEP}]"

DOCS=( README.rst )

src_unpack() {
	if [ "${A}" != "" ]; then
		unpack ${A}
	fi

	cd "${WORKDIR}"
	mv PGPy-${PV} ${P}
}
