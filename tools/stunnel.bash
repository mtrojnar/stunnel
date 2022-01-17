# bash completion for stunnel                              -*- shell-script -*-
# by Michal Trojnara 1998-2022

_comp_cmd_stunnel()
{
    local cur prev words cword
    _init_completion || return

    local opt="-fd -help -version -sockets -options"

    case $prev in
        -fd | -help | -version | -sockets | -options)
            return
            ;;
    esac

    if [[ ${cur} == -* ]] ; then
        COMPREPLY=($(compgen -W "${opt}" -- ${cur}))
        return
    fi

    _filedir '@(cnf|conf)'
} &&
    complete -F _comp_cmd_stunnel stunnel

# ex: filetype=sh
