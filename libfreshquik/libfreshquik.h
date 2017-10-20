//
//  libfreshquik.h
//  freshquik
//
//  Created by msachedi on 2/3/14.
//  Copyright (c) 2014 Tringapps, Inc. All rights reserved.
//

#ifndef freshquik_libfreshquik_h
#define freshquik_libfreshquik_h

int download_with_opts(struct optstruct *opts, const char* db_path, const char* db_owner);
struct optstruct *optadditem(const char *name, const char *arg, int verbose, int toolmask, int ignore,
                          struct optstruct *oldopts);
#endif
