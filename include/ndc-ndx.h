#ifndef NDC_NDX_H
#define NDC_NDX_H

#include <ndx.h>

NDX_DECL(int, on_ndc_init, int, i);
NDX_DECL(int, on_ndc_exit, int, i);
NDX_DECL(int, on_ndc_update, unsigned long long, dt);
NDX_DECL(int, on_ndc_vim, int, fd, int, argc, char **, argv);
NDX_DECL(int, on_ndc_command, int, fd, int, argc, char **, argv);
NDX_DECL(int, on_ndc_connect, int, fd);
NDX_DECL(int, on_ndc_disconnect, int, fd);

#endif
