# $Id$
# Maintainer: Michael Greene <mgreene@securityinnovation.com>
# Contributor: Michael Greene <mgreene@securityinnovation.com>

pkgbase=python-pgpy
pkgname=('python-pgpy' 'python2-pgpy')
pkgver=0.3.0
pkgrel=1
pkgdesc="Pretty Good Privacy for Python - a pure Python OpenPGP implementation."
arch=('any')
license=('BSD')
url="https://github.com/Commod0re/PGPy"
makedepends=('python-setuptools' 'python-cryptography' 'python-singledispatch' 'python-six'
             'python2-setuptools' 'python2-cryptography' 'python2-enum34' 'python2-singledispatch' 'python2-six')
source=("https://pypi.python.org/packages/source/P/PGPy/PGPy-${pkgver}.tar.gz")
##TODO: sum this shit
sha256sums=()
sha384sums=()
sha512sums=()

prepare() {
    cp -a PGPy-${pkgver}{,-python2}
}

build() {
    # Build Python 3 module
    cd ${srcdir}/PGPy-${pkgver}
    python3 setup.py build

    # Build python2 module
    cd ${srcdir}/PGPy-${pkgver}-python2
    python2 setup.py build
}

package_python-pgpy() {
    depends=('python-cryptography>=0.5.2' 'python-cryptography<=0.6' 'python-singledispatch' 'python-six>=1.7.2')

    cd PGPy-${pkgver}
    python3 setup.py install --root="${pkgdir}" --optimize=1 --skip-build
    install -D -m 644 LICENSE ${pkgdir}/usr/share/licenses/python-pgpy/LICENSE
}

package_python2-pgpy() {
    depends=('python2-cryptography>=0.5.2' 'python2-cryptography<=0.6' 
             'python2-six>=1.7.2' 'python2-enum34' 'python-singledispatch')

    cd PGPy-${pkgver}-python2
    python2 setup.py install --root="${pkgdir}" --optimize=1 --skip-build
    install -D -m 644 LICENSE ${pkgdir}/usr/share/licenses/python2-pgpy/LICENSE
}
