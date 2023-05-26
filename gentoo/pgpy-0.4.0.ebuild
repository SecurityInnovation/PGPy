# Copyright 2014 Michael Greene
# Distributed under the terms of the BSD 3-Clause License
# $HEADER: $

EAPI=5
PYTHON_COMPAT=( python{2_7,3_3,3_4,3_5} )

inherit distutils-r1

DESCRIPTION="Pretty Good Privacy for Python - a pure Python OpenPGP implementation."
HOMEPAGE="https://github.com/SecurityInnovation/PGPy"
SRC_URI="https://pypi.python.org/packages/0a/2c/bfe57ac97d31fcd7172df43770d68bab1fbd38d629448ec8013f4714e779/PGPy-0.4.0a.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="~amd64"
IUSE=""

DEPEND="dev-python/setuptools[${PYTHON_USEDEP}]"
RDEPEND="dev-python/singledispatch[${PYTHON_USEDEP}]
         dev-python/pyasn1[${PYTHON_USEDEP}]
         >=dev-python/cryptography-1.1.0[${PYTHON_USEDEP}]
         $(python_gen_cond_dep 'dev-python/enum34[${PYTHON_USEDEP}]' python2_7 python3_3)"
DOCS=( README.rst )

src_unpack() {
    if [ "${A}" != "" ]; then
        unpack ${A}
    fi

    cd "${WORKDIR}"
    mv PGPy-${PV} pgpy-${PV}
}
