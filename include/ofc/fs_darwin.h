/* Copyright (c) 2009 Blue Peach Solutions, Inc.
 * All rights reserved.
 *
 * This software is protected by copyright and intellectual 
 * property laws as well as international treaties.  It is to be 
 * used and copied only by authorized licensees under the 
 * conditions described in their licenses.  
 *
 * Title to and ownership of the software shall at all times 
 * remain with Blue Peach Solutions.
 */

#if !defined(__BLUE_FSDARWIN_H__)
#define __BLUE_FSDARWIN_H__

#include "BlueUtil/BlueTypes.h"
#include "BlueFile/BlueFile.h"

#define BLUE_FS_DARWIN_BLOCK_SIZE 512

/**
 * \defgroup BlueFSDarwin Darwin File System Dependent Support
 * \ingroup BlueFS
 */

/** \{ */

#if defined(__cplusplus)
extern "C"
{
#endif
  BLUE_VOID BlueFSDarwinDestroyOverlapped (BLUE_HANDLE hOverlapped) ;
  BLUE_VOID 
  BlueFSDarwinSetOverlappedOffset (BLUE_HANDLE hOverlapped, BLUE_OFFT offset) ;
  BLUE_VOID BlueFSDarwinStartup (BLUE_VOID) ;
  BLUE_VOID BlueFSDarwinShutdown (BLUE_VOID);
  int BlueFSDarwinGetFD (BLUE_HANDLE) ;
  BLUE_HANDLE BlueFSDarwinGetOverlappedEvent (BLUE_HANDLE hOverlapped) ;
#if defined(__cplusplus)
}
#endif

#endif

/** \} */
