/*

  reload - reloads a snapshot into a windows process, and then injects a DLL inside of it
  to allow manipulation of the process

  there are too many things to count that can go wrong here..
  file handles, window handles, socket handles, and thread/module information
  sockets need to be reconnected (or disconnected and allow the software to reconnect them), or 
  reconnecting the protocl for the software using simulation and then proxying..
  reopening file handles and getting back to the same state
  emulation of window handles and redirecting one handle to another (new handle in a new process)
  some of this requires injection into the process from the beginning but others should work
  with any process

  cryopid does this for linux
*/

#include <windows.h>
