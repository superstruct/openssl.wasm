project('openssl.wasm', ['c'], version: '3.3.2', meson_version: '>=1.3.0', default_options: ['buildtype=release'])

if get_option('simd')
  add_project_arguments('-msimd128', language: 'c')
endif

incs = [ include_directories('include') ]

# For now, build minimal stubs to establish Meson dual-build pathway.
# Full source integration can extend by adding crypto/ and ssl/ sources incrementally.
core = static_library('openssl_core', [], include_directories: incs)

if get_option('main_module')
  executable('openssl-main', 'src/openssl_wasm_module.c',
    link_with: core,
    include_directories: incs,
    install: true,
    link_args: [
      '--no-entry',
      '-sMODULARIZE=1',
      '-sEXPORT_ES6=1',
      '-sALLOW_MEMORY_GROWTH=1',
      '-sENVIRONMENT=web,webview,worker',
      '-sNO_FILESYSTEM=1',
      '-sEXPORTED_RUNTIME_METHODS=["cwrap","ccall","UTF8ToString"]',
      '-sEXPORTED_FUNCTIONS=@' + meson.project_source_root() / get_option('exports'),
    ])
endif

if get_option('side_module')
  shared_module('openssl-side', 'src/openssl_wasm_side.c',
    link_whole: core,
    include_directories: incs,
    name_prefix: '',
    install: true,
    link_args: ['-sSIDE_MODULE=2', '-fPIC'])
endif

