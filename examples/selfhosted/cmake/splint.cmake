option(USE_SPLINT "Set to '1' to run splint, '0' by default" 0)
function(add_splint TARGET)
	if (USE_SPLINT)
		get_directory_property(include_dirs INCLUDE_DIRECTORIES)
		foreach(i ${include_dirs})
			list(APPEND include_flags -I${i})
		endforeach()
		set(SPLINT_ARGS 
			-preproc
			-paramuse
#			-mustfreefresh
#			-retvalother
#			-fixedformalarray
#			-retvalint
#			-nullret
#			-compdef
#			-nullpass
#			-mayaliasunique
#			-temptrans
			)
		add_custom_target(
			splint-${TARGET}
			COMMAND splint ${SPLINT_ARGS} ${include_flags} ${ARGN}
			DEPENDS ${ARGN}
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
		add_dependencies(${TARGET} splint-${TARGET})
	endif() # USE_SPLINT
endfunction() # add_splint