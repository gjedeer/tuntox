# New ports collection Makefile for:    tuntox
# Date created:                         2023-09-28
# Whom:                                 GDR!
#
# $FreeBSD$
#

PORTNAME=       tuntox
PORTVERSION=    0.0.10.1
CATEGORIES=     net-p2p
MASTER_SITES=   GH
PKGNAMEPREFIX=  ${PORTNAME}-

MAINTAINER=     gdr@gdr.name
COMMENT=        Tunnel TCP connections over the Tox protocol 

LICENSE=        GPLv3
LICENSE_FILE=   ${WRKSRC}/LICENSE.md

BUILD_DEPENDS=  /usr/local/lib/libtoxcore.so.2:net-im/tox
BUILD_DEPENDS+=  git:devel/git

RUN_DEPENDS=    /usr/local/lib/libtoxcore.so.2:net-im/tox

USES=           gmake

USE_GITHUB=     yes
GH_ACCOUNT=     gjedeer
GH_PROJECT=     tuntox
GH_TAGNAME=     0adadfebed9bd4a9ffb22e5d248767b32f312a6a

PLIST_FILES=    bin/tuntox

do-build:
	@(cd ${WRKSRC} && ${SETENV} ${MAKE_ENV} ${MAKE_CMD} tuntox_nostatic)

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/tuntox_nostatic ${STAGEDIR}${PREFIX}/bin/tuntox


.include <bsd.port.mk>
