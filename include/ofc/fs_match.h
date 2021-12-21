/* Copyright (c) 2009 Blue Peach Solutions, Inc.
 * All rights reserved.
 *
 * This software is protected by copyright and intellectual 
 * property laws as well as international treaties.  It is to be 
 * used and copied only by authorized licensees under the 
 * conditions described in their licenses.  
 *
 * Title to and ownership of the software shall at all times 
 * remain with Blue Peach Solutions and/or prior copyright holders.
 * 
 * Blue Peach has received permission to use and distribute the software
 * under Blue Peach's terms
 */
#if !defined(__BLUE_FILE_MATCH_H__)
#define __BLUE_FILE_MATCH_H__

#include "ofc/core.h"
#include "ofc/file.h"

#define	BLUE_FILE_MATCH_PATHNAME 0x01  /* No wildcard can ever match `/'. */
#define	BLUE_FILE_MATCH_PERIOD 0x02  /* Leading `.' is matched explicitly. */
#define	BLUE_FILE_MATCH_CASEFOLD 0x04  /* Compare without regard to case.  */

#if defined(__cplusplus)
extern "C" 
{
#endif
  BLUE_CORE_LIB BLUE_BOOL 
  BlueFileMatch (BLUE_CHAR *pattern, BLUE_CHAR *string, BLUE_INT flags);
#if defined(__cplusplus)
}
#endif

#endif
