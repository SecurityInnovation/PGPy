# Copyright 2014 Michael Greene
# Distributed under the terms of the BSD 3-Clause License
# $HEADER: $

EAPI=5
PYTHON_COMPAT=( python{2_7,3_2,3_3} )

inherit distutils-r1

DESCRIPTION="Python 3.4 Enum backported to 3.3, 3.2, 3.1, 2.7, 2.6, 2.5, and 2.4"
HOMEPAGE="https://pypi.python.org/pypi/enum34"
SRC_URI="mirror://pypi/${PN:0:1}/${PN}/${P}.tar.gz"

LICENSE="BSD"
SLOT="0"
KEYWORDS="~x86 ~amd64"
IUSE=""

DEPEND=">=dev-lang/python-2.7[${PYTHON_USEDEP}]"
RDEPEND=">=dev-lang/python-2.7[${PYTHON_USEDEP}]"
DOC=( doc/enum.rst README )
