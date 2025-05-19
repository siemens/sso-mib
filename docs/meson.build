# SPDX-FileCopyrightText: (C) 2024 Siemens AG
# SPDX-License-Identifier: LGPL-2.1-only
doxygen = find_program('doxygen', required : false)
if not doxygen.found()
    error('Program "doxygen" not found or not executable. Try building with -Ddocumentation=false')
endif

src_doxygen = []
foreach f : libsso_mib_hdrs + 'README.md'
    src_doxygen += join_paths(meson.project_source_root(), f)
endforeach

doc_config = configuration_data()
doc_config.set('PACKAGE_NAME', meson.project_name())
doc_config.set('PACKAGE_VERSION', meson.project_version())
doc_config.set('PACKAGE_DESCRIPTION', project_description)
doc_config.set('builddir', meson.current_build_dir())
doc_config.set('apisrcdir', join_paths(meson.project_source_root(), 'include'))
doc_config.set('MAINPAGE', join_paths(meson.project_source_root(), 'README.md'))

doxyfile = configure_file(input : 'doxygen.in',
              output : 'doxygen',
              configuration : doc_config,
              install : false)

custom_target('doxygen',
          input : [ doxyfile ] + src_doxygen,
          output : [ '.' ],
          command : [ doxygen, doxyfile ],
          install : false,
          build_by_default : true)
