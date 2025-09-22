set_xmakever("3.0.1")
set_project("libco")
set_version("0.5.0")

add_rules("mode.debug", "mode.release", "mode.releasedbg")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})

add_defines("_GNU_SOURCE", "_REENTRANT")
set_warnings("all")
set_optimize("faster")
add_cflags("-fno-strict-aliasing","-export-dynamic", "-pipe" ,"-fPIC", "-Wno-deprecated", "-m64")
-- set_languages("asm","c99", "c++11")


add_installfiles("src/*.h", {prefixdir = "include"})

target("co_static")
    set_kind("static")
    add_files("src/*.c","src/coctx_swap.S")
    add_links("pthread", "dl")
    set_filename("libco.a")
    set_languages("c99")

target("co_shared")
    set_kind("shared")
    add_files("src/*.c","src/coctx_swap.S")
    add_links("pthread", "dl")
    set_filename("libco.so")
    set_version("0.5.0")
    set_languages("c99")

for _, f in ipairs(os.files("examples/*.cpp")) do
    local target_name = path.basename(f, ".cpp")
    target(target_name)
        set_kind("binary")
        add_files(f)
        add_deps("co_static")
        add_linkgroups("co",{static = true})
        add_includedirs("src")
        set_languages("c++11")

end
