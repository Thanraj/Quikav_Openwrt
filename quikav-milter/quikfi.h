/*
 *  Copyright (C) 2015 Quik AV, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C)2008 Tringapps, Inc.
 *
 *  Author: aCaB <acab@quikav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef _QUIKFI_H
#define _QUIKFI_H

#include "shared/optparser.h"
#include <libmilter/mfapi.h>

extern uint64_t maxfilesize;
extern int addxvirus;
extern char xvirushdr[255];
extern int multircpt;


sfsistat quikfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t len);
sfsistat quikfi_abort(SMFICTX *ctx);
sfsistat quikfi_eom(SMFICTX *ctx);
sfsistat quikfi_header(SMFICTX *ctx, char *headerf, char *headerv);
sfsistat quikfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr);
sfsistat quikfi_envfrom(SMFICTX *ctx, char **argv);
sfsistat quikfi_envrcpt(SMFICTX *ctx, char **argv);
int init_actions(struct optstruct *opts);

#endif
