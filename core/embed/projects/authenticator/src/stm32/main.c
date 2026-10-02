#include <trezor_rtl.h>

#include "py/builtin.h"
#include "py/gc.h"
#include "py/runtime.h"
#include "py/stackctrl.h"
#include "shared/runtime/pyexec.h"
#include "ports/stm32/gccollect.h"

#include <sys/linker_utils.h>
#include <sys/system.h>

extern const uint8_t g_authenticator_build_audit[8];

int main_func(uint32_t cmd, void *arg) {
  if (((volatile const uint8_t *)g_authenticator_build_audit)[0] != 'A') {
    error_shutdown("Authenticator audit metadata corrupted");
  }
  UNUSED(arg);
  if (cmd != 0) {
    error_shutdown("Authenticator entered unexpected mode");
  }

  mp_stack_set_top(&_stack_section_end);
  mp_stack_set_limit((char *)&_stack_section_end -
                     (char *)&_stack_section_start - 1024);
#if MICROPY_ENABLE_PYSTACK
  static mp_obj_t pystack[1024];
  mp_pystack_init(pystack, &pystack[MP_ARRAY_SIZE(pystack)]);
#endif
  gc_init(&_heap_start, &_heap_end);
  mp_init();
  mp_obj_list_init(mp_sys_path, 0);
  mp_obj_list_append(mp_sys_path, MP_OBJ_NEW_QSTR(MP_QSTR__dot_frozen));
  pyexec_frozen_module("authenticator_boot.py", false);
  mp_deinit();
  error_shutdown("Authenticator stopped");
  return 1;
}

void __attribute__((noreturn)) nlr_jump_fail(void *val) {
  UNUSED(val);
  error_shutdown("Authenticator exception");
}

mp_import_stat_t mp_import_stat(const char *path) {
  UNUSED(path);
  return MP_IMPORT_STAT_NO_EXIST;
}

mp_obj_t mp_builtin_open(uint n_args, const mp_obj_t *args, mp_map_t *kwargs) {
  UNUSED(n_args);
  UNUSED(args);
  UNUSED(kwargs);
  return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_KW(mp_builtin_open_obj, 1, mp_builtin_open);

__attribute((no_stack_protector)) void reset_handler(uint32_t cmd, void *arg,
                                                     uint32_t random_value) {
  init_linker_sections();
  extern uint32_t __stack_chk_guard;
  __stack_chk_guard = random_value;
  system_exit(main_func(cmd, arg));
}
