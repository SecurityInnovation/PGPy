# $Id$
# Maintainer: Michael Greene <mgreene@securityinnovation.com>
# Contributor: Michael Greene <mgreene@securityinnovation.com>

pkgbase=python-pgpy
pkgname=('python-pgpy' 'python2-pgpy')
pkgver=0.2.3
pkgrel=1
pkgdesc="Pretty Good Privacy for Python - a pure Python OpenPGP implementation."
arch=('any')
license=('BSD')
url="https://github.com/Commod0re/PGPy"
makedepends=('python-setuptools' 'python2-setuptools' 'python-cryptography'
             'python-six' 'python2-cryptography' 'python2-enum34' 'python2-singledispatch' 'python2-six')
checkdepends=('wget' 'python-pytest' 'python2-pytest' 'pgpdump-git' 'gnupg')
checkdepends+=('python' 'python-six' 'python-cryptography>=0.6' 'python-cryptography<0.6.1')
checkdepends+=('python2' 'python2-six' 'python2-enum34' 'python2-singledispatch' 
               'python2-cryptography>=0.6' 'python2-cryptography<0.6.1')
source=("https://pypi.python.org/packages/source/P/PGPy/PGPy-${pkgver}.tar.gz")
sha256sums=("5286a625b6476cd254a59855424d424adcfc61c2079163ef0f4a975508336e38")

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

check() {
    [ -f PGPy-github-${pkgver}.tar.gz ] || wget ${url}/archive/${pkgver}.tar.gz -O PGPy-github-${pkgver}.tar.gz
    ##TODO: when updating to 0.3.0, this can probably change back to normal
    # tar -zxvf PGPy-github-${pkgver}.tar.gz -- PGPy-${pkgver}/{tox.ini,requirements-test.txt,tests}
    mkdir -p ${srcdir}/PGPy
    tar -C PGPy -zxvf PGPy-github-${pkgver}.tar.gz --strip-components=1
    cd PGPy

    # test Python 3
    py.test tests/

    # test Python 2
    py.test2 tests/
}

package_python-pgpy() {
    depends=('python-six' 'python-cryptography>=0.6' 'python-cryptography<0.6.1')

    cd PGPy-${pkgver}
    python3 setup.py install --root="${pkgdir}" --optimize=1 --skip-build
    install -D -m 644 LICENSE ${pkgdir}/usr/share/licenses/python-pgpy/LICENSE
}

package_python2-pgpy() {
    depends=('python2-six' 'python2-enum34' 'python2-singledispatch' 
             'python2-cryptography>=0.6' 'python2-cryptography<0.6.1')

    cd PGPy-${pkgver}-python2
    python2 setup.py install --root="${pkgdir}" --optimize=1 --skip-build
    install -D -m 644 LICENSE ${pkgdir}/usr/share/licenses/python2-pgpy/LICENSE
}
