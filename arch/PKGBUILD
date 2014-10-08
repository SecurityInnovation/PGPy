# $Id$
# Maintainer: Michael Greene <mgreene@securityinnovation.com>

pkgbase=python-pgpy
pkgname=('python-pgpy' 'python2-pgpy')
pkgver=0.2.3
pkgrel=1
pkgdesc="Pretty Good Privacy for Python - a pure Python OpenPGP implementation."
arch=('i686' 'x86_64')
license=('BSD')
url="https://github.com/Commod0re/PGPy"
makedepends=('python-setuptools' 'python2-setuptools')
checkdepends=()
source=("https://pypi.python.org/packages/source/P/PGPy/PGPy-${pkgver}.tar.gz")
sha256sums=("5286a625b6476cd254a59855424d424adcfc61c2079163ef0f4a975508336e38")

prepare() {
    cp -a PGPy-${pkgver}{,-python2}
}

build() {
    # Build Python 3 module
    cd PGPy-${pkgver}
    python3 setup.py build

    # Build python2 module
    cd ../PGPy-${pkgver}-python2
    python2 setup.py build
}

package_python-pgpy() {
    depends=('python' 'python-six' 'python-cryptography>=0.6' 'python-cryptography<0.6.1')

    cd PGPy-${pkgver}
    python3 setup.py install --root="${pkgdir}" --optimize=1 --skip-build
}

package_python2-pgpy() {
    depends=('python2' 'python2-six' 'python2-enum34' 'python2-singledispatch')

    cd PGPy-${pkgver}-python2
    python2 setup.py install --root="${pkgdir}" --optimize=1 --skip-build
}
