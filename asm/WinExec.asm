[BITS 32]

global __start

section .text

__start:
  cld                    ; required for block_api.asm
  call startup

delta:
  %include "block_api.asm"
  
startup:
execute:
  pop ebp                ; Pop off the address of 'api_call' for calling later.
  push byte +1           ;
  lea eax, [ebp+command-delta]
  push eax               ;
  push 0x876F8B31        ; hash( "kernel32.dll", "WinExec" )
  call ebp               ; WinExec( &command, 1 );

exit:
  %include "block_exitfunk.asm"

command:
  db "calc.exe", 0
