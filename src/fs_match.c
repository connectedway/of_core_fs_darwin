/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
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
