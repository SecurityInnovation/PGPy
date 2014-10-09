# Copyright 2014 Michael Greene
# Distributed under the terms of the BSD 3-Clause License
# $HEADER: $

EAPI=5
PYTHON_COMPAT=( python{2_7,3_2,3_3,3_4} )

inherit distutils-r1

DESCRIPTION="Pretty Good Privacy for Python - a pure Python OpenPGP implementation."
HOMEPAGE="https://github.com/Commod0re/PGPy"
SRC_URI="mirror://pypi/P/PGPy/PGPy-${PV}.tar.gz"

LICENSE="BSD"
SLOT="0"
IUSE="test"

DEPEND="dev-python/setuptools[${PYTHON_USEDEP}]"
RDEPEND="dev-python/six[${PYTHON_USEDEP}]
         dev-python/singledispatch[${PYTHON_USEDEP}]
         dev-python/enum34[${PYTHON_USEDEP}]
         >=dev-python/cryptography-0.5.4[${PYTHON_USEDEP}]
         test? (
            dev-python/pytest[${PYTHON_USEDEP}]
            net-misc/wget
            app-arch/tar
         )"
DOCS=( README.rst )

python_test() {
    wget ${HOMEPAGE}/archive/${PV}.tar.gz -O PGPy-github-${PV}.tar.gz
    mkdir PGPy
    tar -C PGPy -zxvf PGPy-github-${PV}.tar.gz --strip-components=1
    cd PGPy
    py.test tests/ || die
}
