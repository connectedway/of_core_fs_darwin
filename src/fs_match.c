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

#include "ofc/core.h"
#include "ofc/types.h"
#include "ofc/libc.h"
#include "ofc/fs_match.h"

static BLUE_CHAR 
BlueFileMatchLower (BLUE_INT flags, BLUE_CHAR c)
{
  if (flags & BLUE_FILE_MATCH_CASEFOLD)
    {
      c = BLUE_C_TOLOWER(c) ;
    }
  return (c) ;
}


BLUE_CORE_LIB BLUE_BOOL 
BlueFileMatch (BLUE_CHAR *pattern, BLUE_CHAR *name, BLUE_INT flags)
{
  BLUE_BOOL ret ;

  ret = BLUE_TRUE ;
  if (pattern != BLUE_NULL)
    {
      for ( ; *pattern != '\0' && ret == BLUE_TRUE ; )
	{
	  /*
	   * Dispatch on the pattern character
	   */
	  switch (*pattern)
	    {
	    case '?':
	      pattern++ ;
	      /*
	       * Match any one character
	       */
	      if (*name == '\0')
		/*
		 * Trying to match end of string.  That's a failure
		 */
		ret = BLUE_FALSE ;
	      else
		{
		  if (*name == '.')
		    ret = BLUE_FALSE ;
		  else
		    /*
		     * Matched the character, on to the next
		     */
		    name++ ;
		}
	      break;

	    case '\\':
	      /*
	       * Escape, so let's use the next character as is
	       */
	      pattern++ ;

	      if (BlueFileMatchLower (flags, *pattern)  != 
		  BlueFileMatchLower (flags, *name))
		ret = BLUE_FALSE ;
	      else
		{
		  /*
		   * Matched, on to next
		   */
		  pattern++ ;
		  name++ ;
		}
	      break ;

	    case '*':
	      if (*name != '\0')
		{
		  pattern++ ;
		  name++ ;
		}
	      /*
	       * Eat extra wildcards
	       */
	      for ( ; *pattern == '*' ; pattern++) ;
	      if (*pattern != '\0')
		{
		  /*
		   * We need to recursively try to match strings
		   */
		  for ( ; *name != '\0' && 
			  BlueFileMatch (pattern, name, flags) == BLUE_FALSE ; 
			name++) ;

		  if (*name == '\0')
		    ret = BLUE_FALSE ;
		  else
		    pattern += BlueCstrlen (pattern) ;
		}
	      break ;

	    default:
	      if (BlueFileMatchLower (flags, *pattern) != 
		  BlueFileMatchLower (flags, *name))
		ret = BLUE_FALSE ;
	      else
		{
		  pattern++ ;
		  name++ ;
		}
	      break ;
	    }
	}
    }

  return (ret) ;
}
