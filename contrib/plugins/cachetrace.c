#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qemu-plugin.h>

/* ===--------------------------------------------------------------------=== */
// Global plugin state and structures
/* ===--------------------------------------------------------------------=== */

static struct {
  // Dump file for cache trace
  FILE *dump_file;
  // Are we capturing cache trace?
  bool is_capturing;
  // Capture r or w?
  enum qemu_plugin_mem_rw rw;
  // How many transactions have been captured?
  uint64_t trans_captured;
} plugin_state;

// MAGIC_INST: movabsq rax, 0xcafebabedeadbeef
static const uint8_t MAGIC_INST[] = {0x48, 0xb8, 0xef, 0xbe, 0xad,
                                     0xde, 0xbe, 0xba, 0xfe, 0xca};

// Check if the instruction is the magic instruction
static inline bool is_magic_inst(void const *data, size_t size) {
  return size == sizeof(MAGIC_INST) &&
         memcmp(data, MAGIC_INST, sizeof(MAGIC_INST)) == 0;
}

/* ===--------------------------------------------------------------------=== */
// Emulation helper functions
/* ===--------------------------------------------------------------------=== */

/* ===--------------------------------------------------------------------=== */
// Plugin callback functions
/* ===--------------------------------------------------------------------=== */

// Event: On VCPU initialization
static void cb_vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
  (void)id;
  (void)vcpu_index;
}

// Event: On magic instruction execution
static void cb_vcpu_magic_insn_exec(unsigned int cpu_index, void *udata) {
  (void)udata;
  plugin_state.is_capturing = !plugin_state.is_capturing;
  qemu_plugin_outs("Magic instruction executed\n");
  if (plugin_state.is_capturing) {
    qemu_plugin_outs("Start capturing cache trace\n");
  } else {
    qemu_plugin_outs("Stopped capturing cache trace\n");
    g_autoptr(GString) msg = g_string_new("Number of transactions captured: ");
    g_string_append_printf(msg, "%" PRIu64 "\n", plugin_state.trans_captured);
    qemu_plugin_outs(msg->str);
  }
}

// Event: On memory access
static void cb_vcpu_mem_access(unsigned int vcpu_index,
                               qemu_plugin_meminfo_t info, uint64_t vaddr,
                               void *userdata) {
  struct qemu_plugin_hwaddr *hwaddr;
  uint64_t physical_addr;
  if (!plugin_state.is_capturing) {
    return;
  }
  hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
  if (!hwaddr || qemu_plugin_hwaddr_is_io(hwaddr)) {
    return;
  }
  physical_addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
  // Dump the memory access to the file
  fwrite(&physical_addr, sizeof(physical_addr), 1, plugin_state.dump_file);
  plugin_state.trans_captured++;
}

// Event: On translation block new translation
static void cb_vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
  struct qemu_plugin_insn *insn;
  void const *insn_data;
  size_t insn_data_size;
  const size_t n = qemu_plugin_tb_n_insns(tb);
  // Find the magic instruction in the TB and register a callback
  for (size_t i = 0; i < n; i++) {
    insn = qemu_plugin_tb_get_insn(tb, i);
    insn_data = qemu_plugin_insn_data(insn);
    insn_data_size = qemu_plugin_insn_size(insn);
    // If the current instruction is the magic instruction, register a callback
    if (is_magic_inst(insn_data, insn_data_size)) {
      qemu_plugin_register_vcpu_insn_exec_cb(insn, cb_vcpu_magic_insn_exec,
                                             QEMU_PLUGIN_CB_NO_REGS, NULL);
      continue;
    }
    // Otherwise, just capture the (data) memory access
    qemu_plugin_register_vcpu_mem_cb(insn, cb_vcpu_mem_access,
                                     QEMU_PLUGIN_CB_NO_REGS, plugin_state.rw,
                                     NULL);
  }
}

// Event: On plugin exit
static void cb_plugin_exit(qemu_plugin_id_t id, void *p) {
  (void)id;
  (void)p;
  // Write the number of transactions captured to the beginning of the dump file
  fseek(plugin_state.dump_file, 0, SEEK_SET);
  fwrite(&plugin_state.trans_captured, sizeof(plugin_state.trans_captured), 1,
         plugin_state.dump_file);
  // Close the dump file
  fclose(plugin_state.dump_file);
}

/* ===--------------------------------------------------------------------=== */
// Plugin registration
/* ===--------------------------------------------------------------------=== */

// Declare the QEMU plugin API version
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

// This function is called when the plugin is loaded
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv) {
  // Parse the command line options
  for (int i = 0; i < argc; i++) {
    char *opt = argv[i];
    g_auto(GStrv) parts = g_strsplit(opt, "=", 2);
    if (g_strcmp0(parts[0], "dump") == 0) {
      plugin_state.dump_file = fopen(parts[1], "wb");
      if (!plugin_state.dump_file) {
        fprintf(stderr, "Failed to open dump file: %s\n", parts[1]);
        return -1;
      }
    } else {
      fprintf(stderr, "Unknown option: %s\n", opt);
      return -1;
    }
  }

  // Sanity check the options
  if (!plugin_state.dump_file) {
    fprintf(stderr, "Missing required option: dump\n");
    return -1;
  }
  if (!info->system_emulation) {
    fprintf(stderr, "This plugin is for system emulation only\n");
    return -1;
  }
  if (info->system.max_vcpus > 1) {
    fprintf(stderr, "This plugin is for single-CPU emulation only\n");
    return -1;
  }
  if (g_strcmp0(info->target_name, "x86_64")) {
    fprintf(stderr, "Unsupported target: %s\n", info->target_name);
    fprintf(stderr, "This plugin is for x86_64 target only\n");
    return -1;
  }

  // Set up the plugin state
  plugin_state.is_capturing = false;
  plugin_state.rw = QEMU_PLUGIN_MEM_RW;
  plugin_state.trans_captured = 0;
  qemu_plugin_outs("Initialized cache trace plugin\n");

  // Write empty bytes to the beginning of the dump file indicating the number
  // of transactions that will be captured
  {
    uint64_t zero = 0;
    fwrite(&zero, sizeof(zero), 1, plugin_state.dump_file);
  }

  // Register init, translation block and exit callbacks
  qemu_plugin_register_vcpu_init_cb(id, cb_vcpu_init);
  qemu_plugin_register_vcpu_tb_trans_cb(id, cb_vcpu_tb_trans);
  qemu_plugin_register_atexit_cb(id, cb_plugin_exit, NULL);

  return 0;
}
