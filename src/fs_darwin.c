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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <aio.h>
#include <signal.h>
#include <unistd.h>

#include "ofc/types.h"
#include "ofc/handle.h"
#include "ofc/queue.h"
#include "ofc/libc.h"
#include "ofc/path.h"
#include "ofc/lock.h"
#include "ofc/event.h"
#include "ofc/thread.h"
#include "ofc/time.h"

#include "ofc/heap.h"
#include "ofc/fs.h"

#include "ofc/fs_darwin.h"
#include "ofc/fs_match.h"

/**
 * \defgroup BlueFSDarwin Darwin File Interface
 *
 * \ingroup BlueFS
 */

/** \{ */
typedef struct 
{
  int fd ;
  BLUE_BOOL deleteOnClose ;
  BLUE_CHAR *name ;
  BLUE_CHAR *pattern ;
  DIR *dir ;
  struct dirent nextDirent ;
  int nextRet ;
  BLUE_BOOL backup ;
} BLUE_FS_DARWIN_CONTEXT ;

typedef enum
  {
    BLUE_FSDARWIN_READ,
    BLUE_FSDARWIN_WRITE,
    BLUE_FSDARWIN_NOOP
  } BLUE_FSDARWIN_OP ;

typedef struct
{
  BLUE_FSDARWIN_OP opcode ;
  BLUE_HANDLE hEvent ;
  BLUE_HANDLE hBusy ;
  BLUE_INT dwResult ;
  BLUE_INT Errno ;
  BLUE_OFFT offset ;
  BLUE_HANDLE hThread ;
  BLUE_LPCVOID lpBuffer ;
  BLUE_DWORD nNumberOfBytes ;
  BLUE_INT fd ;
} BLUE_FSDARWIN_OVERLAPPED ;

BLUE_HANDLE BlueFSDarwinAIOFreeQ ;
static BLUE_INT g_instance ;


/*
 * Error codes
 */
typedef struct
{
  BLUE_UINT32 file_errno ;
  BLUE_UINT32 blue_error ;
} ERRNO2FILE ;

#define ERRNO2FILE_MAX 34
static ERRNO2FILE errno2file[ERRNO2FILE_MAX] =
  {
    {EPERM, BLUE_ERROR_ACCESS_DENIED},
    {ENOENT, BLUE_ERROR_FILE_NOT_FOUND},
    {ESRCH, BLUE_ERROR_INVALID_HANDLE},
    {EINTR, BLUE_ERROR_GEN_FAILURE},
    {EIO, BLUE_ERROR_IO_DEVICE},
    {ENXIO, BLUE_ERROR_BAD_DEVICE},
    {EBADF, BLUE_ERROR_INVALID_HANDLE},
    {EDEADLK, BLUE_ERROR_LOCK_VIOLATION},
    {EACCES, BLUE_ERROR_INVALID_ACCESS},
    {EFAULT, BLUE_ERROR_INVALID_PARAMETER},
    {EBUSY, BLUE_ERROR_BUSY},
    {EEXIST, BLUE_ERROR_FILE_EXISTS},
    {EXDEV, BLUE_ERROR_NOT_SAME_DEVICE},
    {ENOTDIR, BLUE_ERROR_INVALID_ACCESS},
    {EISDIR, BLUE_ERROR_DIRECTORY},
    {EINVAL, BLUE_ERROR_BAD_ARGUMENTS},
    {ENFILE, BLUE_ERROR_TOO_MANY_OPEN_FILES},
    {EMFILE, BLUE_ERROR_TOO_MANY_OPEN_FILES},
    {ETXTBSY, BLUE_ERROR_BUSY},
    {EFBIG, BLUE_ERROR_FILE_INVALID},
    {ENOSPC, BLUE_ERROR_DISK_FULL},
    {ESPIPE, BLUE_ERROR_SEEK_ON_DEVICE},
    {EROFS, BLUE_ERROR_WRITE_PROTECT},
    {EPIPE, BLUE_ERROR_BROKEN_PIPE},
    {EAGAIN, BLUE_ERROR_IO_INCOMPLETE},
    {EINPROGRESS, BLUE_ERROR_IO_PENDING},
    {EOPNOTSUPP, BLUE_ERROR_NOT_SUPPORTED},
    {ELOOP, BLUE_ERROR_BAD_PATHNAME},
    {ENAMETOOLONG, BLUE_ERROR_BAD_PATHNAME},
    {ENOTEMPTY, BLUE_ERROR_DIR_NOT_EMPTY},
    {EDQUOT, BLUE_ERROR_HANDLE_DISK_FULL},
    {ENOSYS, BLUE_ERROR_NOT_SUPPORTED},
    {EOVERFLOW, BLUE_ERROR_BUFFER_OVERFLOW},
    {ECANCELED, BLUE_ERROR_OPERATION_ABORTED}
  } ;

static BLUE_DWORD 
BlueFSDarwinAIOThread (BLUE_HANDLE hThread, BLUE_VOID *context) ;

static BLUE_UINT32 TranslateError (BLUE_UINT32 file_errno)
{
  BLUE_INT low ;
  BLUE_INT high ;
  BLUE_INT cursor ;
  BLUE_UINT32 blue_error ;

  blue_error = BLUE_ERROR_GEN_FAILURE ;
  low = 0 ;
  high = ERRNO2FILE_MAX - 1 ;
  cursor = high + low / 2 ;
  while (errno2file[cursor].file_errno != file_errno && low <= high )
    {
      if (file_errno < errno2file[cursor].file_errno)
	high = cursor - 1;
      else
	low = cursor + 1 ;
      cursor = high + low / 2 ;
    }
  if (errno2file[cursor].file_errno == file_errno)
    blue_error = errno2file[cursor].blue_error ;

  return (blue_error) ;
}

static int Win32DesiredAccessToDarwinFlags (BLUE_DWORD dwDesiredAccess)
{
  static BLUE_DWORD dwWriteAccess =
    BLUE_FILE_ADD_FILE | BLUE_FILE_ADD_SUBDIRECTORY |
    BLUE_FILE_APPEND_DATA |
    BLUE_FILE_DELETE_CHILD |
    BLUE_FILE_WRITE_ATTRIBUTES | BLUE_FILE_WRITE_DATA |
    BLUE_FILE_WRITE_EA |
    BLUE_GENERIC_WRITE ;
  static BLUE_DWORD dwReadAccess =
    BLUE_FILE_LIST_DIRECTORY |
    BLUE_FILE_READ_ATTRIBUTES | BLUE_FILE_READ_DATA |
    BLUE_FILE_READ_EA | BLUE_FILE_TRAVERSE |
    BLUE_GENERIC_READ ;
  static BLUE_DWORD dwExecuteAccess =
    BLUE_FILE_EXECUTE |
    BLUE_GENERIC_EXECUTE ;

  int oflag ;

  oflag = 0 ;
  if (dwDesiredAccess & dwWriteAccess)
    {
      if ((dwDesiredAccess & dwReadAccess) ||
	  (dwDesiredAccess & dwExecuteAccess))
	oflag = O_RDWR ;
      else
	oflag = O_WRONLY ;
    }
  else
    oflag = O_RDONLY ;

  return (oflag) ;
}

static int 
Win32CreationDispositionToDarwinFlags (BLUE_DWORD dwCreationDisposition)
{
  int oflag ;

  static int map[6] =
    {
      /* Unused - 0 */
      0,
      /* Create New - 1 */
      O_CREAT | O_EXCL,
      /* Create Always - 2 */
      O_CREAT | O_TRUNC,
      /* Open Existing - 3 */
      0,
      /* Open Always - 4 */
      O_CREAT,
      /* Truncate Existing - 5 */
      O_TRUNC
    } ;

  oflag = 0 ;
  if (dwCreationDisposition >= BLUE_CREATE_NEW && 
      dwCreationDisposition <= BLUE_TRUNCATE_EXISTING)
    oflag = map[dwCreationDisposition] ;
  return (oflag) ;
}

static int Win32FlagsAndAttrsToDarwinFlags (BLUE_DWORD dwFlagsAndAttributes)
{
  int oflag ;

  oflag = 0 ;
  return (oflag) ;
}

static BLUE_VOID Win32OpenModesToDarwinModes (BLUE_DWORD dwDesiredAccess, 
					     BLUE_DWORD dwShareMode,
					     BLUE_DWORD dwCreationDisposition, 
					     BLUE_DWORD dwFlagsAndAttributes,
					     int *oflag, mode_t *mode) 
{
  *mode = S_IRWXU | S_IRWXG | S_IRWXO ;

  /*
   * First do dwDesired Access
   */
  *oflag = 0 ;
  *oflag |= Win32DesiredAccessToDarwinFlags (dwDesiredAccess) ;
  /*
   * Darwin doesn't have a share mode
   */
  /*
   * Creation Disposition
   */
  *oflag |= Win32CreationDispositionToDarwinFlags (dwCreationDisposition) ;
  /*
   * Flags and Attributes
   */
  *oflag |= Win32FlagsAndAttrsToDarwinFlags (dwFlagsAndAttributes) ;
  /*
   * Some stragglers
   */
  if (dwDesiredAccess & BLUE_FILE_APPEND_DATA &&
      (!(dwDesiredAccess & BLUE_FILE_WRITE_DATA)))
    *oflag |= O_APPEND ;
}

static BLUE_LPSTR FilePath2DarwinPath (BLUE_LPCTSTR lpFileName)
{
  BLUE_LPCTSTR p ;
  BLUE_LPSTR lpAsciiName ;

  p = lpFileName ;
  if (BlueCtstrncmp (lpFileName, TSTR("file:"), 5) == 0)
    p = lpFileName + 5 ;
  lpAsciiName = BlueCtstr2cstr (p) ;

  return (lpAsciiName) ;
}

static BLUE_HANDLE BlueFSDarwinCreateFile (BLUE_LPCTSTR lpFileName,
					  BLUE_DWORD dwDesiredAccess,
					  BLUE_DWORD dwShareMode,
					  BLUE_LPSECURITY_ATTRIBUTES 
					  lpSecAttributes,
					  BLUE_DWORD dwCreationDisposition,
					  BLUE_DWORD dwFlagsAndAttributes,
					  BLUE_HANDLE hTemplateFile)
{
  BLUE_HANDLE ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  int oflag ;
  mode_t mode ;
  BLUE_CHAR *lpAsciiName ;

  context = BlueHeapMalloc (sizeof (BLUE_FS_DARWIN_CONTEXT)) ;
  context->fd = -1 ;
  context->deleteOnClose = BLUE_FALSE ;
  context->backup = BLUE_FALSE ;

  Win32OpenModesToDarwinModes (dwDesiredAccess, dwShareMode,
			      dwCreationDisposition, dwFlagsAndAttributes,
			      &oflag, &mode) ;
  
  if (dwFlagsAndAttributes & BLUE_FILE_FLAG_DELETE_ON_CLOSE)
    context->deleteOnClose = BLUE_TRUE ;

  /*
   * Strip and convert to non-unicode
   */
  lpAsciiName = FilePath2DarwinPath (lpFileName) ;

  context->name = BlueCstrdup (lpAsciiName) ;

  if (!(dwFlagsAndAttributes & BLUE_FILE_FLAG_BACKUP_SEMANTICS))
    {
      context->fd = open (lpAsciiName, oflag, mode) ;
      if (context->fd < 0)
	{
	  BlueThreadSetVariable (BlueLastError, 
				 (BLUE_DWORD_PTR) TranslateError(errno)) ;
	  BlueHeapFree (context->name) ;
	  BlueHeapFree (context) ;
	  ret = BLUE_INVALID_HANDLE_VALUE ;
	}
      else
	ret = BlueHandleCreate (BLUE_HANDLE_FSDARWIN_FILE, context) ;
    }
  else
    {
      ret = BlueHandleCreate (BLUE_HANDLE_FSDARWIN_FILE, context) ;
      context->backup = BLUE_TRUE ;
    }

  BlueHeapFree (lpAsciiName) ;

  return (ret) ;
}

static BLUE_BOOL 
BlueFSDarwinCreateDirectory (BLUE_LPCTSTR lpPathName,
			    BLUE_LPSECURITY_ATTRIBUTES lpSecurityAttr) 
{
  BLUE_BOOL ret ;
  int status ;
  mode_t mode ;
  BLUE_CHAR *lpAsciiName ;

  lpAsciiName = FilePath2DarwinPath (lpPathName) ;
  mode = S_IRWXU | S_IRWXG | S_IRWXO ;

  status = mkdir (lpAsciiName, mode) ;

  BlueHeapFree (lpAsciiName) ;
  if (status < 0)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(errno)) ;
      ret = BLUE_FALSE ;
    }
  else
    ret = BLUE_TRUE ;

  return (ret) ;
}

static BLUE_BOOL BlueFSDarwinWriteFile (BLUE_HANDLE hFile,
				       BLUE_LPCVOID lpBuffer,
				       BLUE_DWORD nNumberOfBytesToWrite,
				       BLUE_LPDWORD lpNumberOfBytesWritten,
				       BLUE_HANDLE hOverlapped)
{
  BLUE_BOOL ret ;
  ssize_t status ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;

  ret = BLUE_FALSE ;
  context = BlueHandleLock (hFile) ;

  if (context == BLUE_NULL || context->backup)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      Overlapped = BLUE_NULL ;
      if (hOverlapped != BLUE_HANDLE_NULL)
	{
	  Overlapped = BlueHandleLock (hOverlapped) ;
	}

      if (Overlapped != BLUE_NULL)
	{
	  BlueEventReset (Overlapped->hEvent) ;
	  Overlapped->fd = context->fd ;
	  Overlapped->lpBuffer = lpBuffer ;
	  Overlapped->nNumberOfBytes = nNumberOfBytesToWrite ;
	  Overlapped->opcode = BLUE_FSDARWIN_WRITE ;

	  BlueCTrace ("aio_write 0x%08x\n", 
		      (BLUE_INT) Overlapped->offset) ;

	  BlueEventSet (Overlapped->hBusy) ;

	  BlueThreadSetVariable (BlueLastError, (BLUE_DWORD_PTR) 
				 TranslateError(EINPROGRESS)) ;

	  BlueHandleUnlock (hOverlapped) ;
	  ret = BLUE_FALSE ;
	}
      else
	{
	  status = write (context->fd, lpBuffer, nNumberOfBytesToWrite) ;

	  if (status >= 0)
	    {
	      if (lpNumberOfBytesWritten != BLUE_NULL)
		*lpNumberOfBytesWritten = (BLUE_DWORD) status ;
	      ret = BLUE_TRUE ;
	    }
	  else
	    {
	      BlueThreadSetVariable (BlueLastError, 
				     (BLUE_DWORD_PTR) TranslateError(errno)) ;
	      ret = BLUE_FALSE ;
	    }
	}
    }

  if (context != BLUE_NULL)
    BlueHandleUnlock (hFile) ;

  return (ret) ;
}

static BLUE_BOOL BlueFSDarwinReadFile (BLUE_HANDLE hFile,
				      BLUE_LPVOID lpBuffer,
				      BLUE_DWORD nNumberOfBytesToRead,
				      BLUE_LPDWORD lpNumberOfBytesRead,
				      BLUE_HANDLE hOverlapped)
{
  BLUE_BOOL ret ;
  ssize_t status ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;

  ret = BLUE_FALSE ;
  context = BlueHandleLock (hFile) ;

  if (context == BLUE_NULL || context->backup)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      Overlapped = BLUE_NULL ;
      if (hOverlapped != BLUE_HANDLE_NULL)
	Overlapped = BlueHandleLock (hOverlapped) ;

      if (Overlapped != BLUE_NULL)
	{
	  /*
	   * Offset should already be set
	   */
	  BlueEventReset (Overlapped->hEvent) ;
	  Overlapped->fd = context->fd ;
	  Overlapped->lpBuffer = lpBuffer ;
	  Overlapped->nNumberOfBytes = nNumberOfBytesToRead ;
	  Overlapped->opcode = BLUE_FSDARWIN_READ ;

	  BlueCTrace ("aio_read 0x%08x\n", 
		      (BLUE_INT) Overlapped->offset) ;

	  BlueEventSet (Overlapped->hBusy) ;

	  BlueThreadSetVariable (BlueLastError, 
				 (BLUE_DWORD_PTR) TranslateError(EINPROGRESS)) ;

	  BlueHandleUnlock (hOverlapped) ;
	  ret = BLUE_FALSE ;
	}
      else
	{
	  status = read (context->fd, lpBuffer, nNumberOfBytesToRead) ;

	  if (status > 0)
	    {
	      if (lpNumberOfBytesRead != BLUE_NULL)
		*lpNumberOfBytesRead = (BLUE_DWORD) status ;
	      ret = BLUE_TRUE ;
	    }
	  else
	    {
	      ret = BLUE_FALSE ;
	      if(status == 0)
		BlueThreadSetVariable (BlueLastError, (BLUE_DWORD_PTR) 
				       BLUE_ERROR_HANDLE_EOF) ;
	      else
		BlueThreadSetVariable (BlueLastError, (BLUE_DWORD_PTR) 
				       TranslateError(errno)) ;
	    }
	}
    }

  if (context != BLUE_NULL)
    BlueHandleUnlock (hFile) ;

  return (ret) ;
}

static BLUE_BOOL BlueFSDarwinCloseHandle (BLUE_HANDLE hFile)
{
  BLUE_BOOL ret ;
  int status ;
  BLUE_FS_DARWIN_CONTEXT *context ;

  ret = BLUE_FALSE ;
  context = BlueHandleLock (hFile) ;

  if (context == BLUE_NULL)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      if (context->fd == -1 || context->backup)
	status = 0 ;
      else
	status = close (context->fd) ;

      if (status >= 0)
	{
	  if (context->deleteOnClose)
	    {
	      /*
	       * Might be a directory, might be a file
	       */
	      rmdir (context->name) ;
	      unlink (context->name) ;
	    }

	  BlueHandleDestroy (hFile) ;
	  BlueHeapFree (context->name) ;
	  BlueHeapFree (context) ;
	  ret = BLUE_TRUE ;
	}
      else
	{
	  ret = BLUE_FALSE ;
	  BlueThreadSetVariable (BlueLastError, 
				 (BLUE_DWORD_PTR) TranslateError(errno)) ;
	}
      BlueHandleUnlock (hFile) ;
    }

  return (ret) ;

}

static BLUE_BOOL BlueFSDarwinDeleteFile (BLUE_LPCTSTR lpFileName) 
{
  BLUE_BOOL ret ;
  int status ;
  BLUE_CHAR *asciiName ;
  

  ret = BLUE_TRUE ;
  asciiName = FilePath2DarwinPath (lpFileName) ;

  status = unlink (asciiName) ;
  BlueHeapFree (asciiName) ;

  if (status < 0)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(errno)) ;
      ret = BLUE_FALSE ;
    }

  return (ret) ;
}

static BLUE_BOOL BlueFSDarwinRemoveDirectory (BLUE_LPCTSTR lpPathName) 
{
  BLUE_BOOL ret ;
  int status ;
  BLUE_CHAR *asciiName ;

  ret = BLUE_TRUE ;
  asciiName = FilePath2DarwinPath (lpPathName) ;
  status = rmdir (asciiName) ;

  BlueHeapFree (asciiName) ;
  if (status < 0)
    {
      ret = BLUE_FALSE ;
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}

static BLUE_BOOL GetWin32FindFileData (BLUE_CHAR *asciiName, 
				       BLUE_CCHAR *dName,
				       BLUE_LPWIN32_FIND_DATAW lpFindFileData)

{
  struct stat sb ;
  int status ;
  BLUE_BOOL ret ;
  BLUE_TCHAR *tcharName ;

  ret = BLUE_FALSE ;
  status = stat (asciiName, &sb) ;
  if (status == -1)
    {
      /*
       * See if it's a link.  If so, we still want to show it.  The reason
       * we use stat rather then lstat initially is we do want the 
       * target of the link.  We only want to revert to the link when 
       * the target returns an error.
       */
      status = lstat (asciiName, &sb) ;
    }

  if (status >= 0)
    {
      lpFindFileData->dwFileAttributes = 0 ;
      /*
       * We do not support hidden files or System Files or Archive Files
       * or temporary or sparse or compressed,or offline, or encrypted,
       * or virtual
       */
      
      if (sb.st_flags & UF_IMMUTABLE)
	lpFindFileData->dwFileAttributes |= BLUE_FILE_ATTRIBUTE_READONLY ;
      if (sb.st_mode & S_IFDIR)
	lpFindFileData->dwFileAttributes |= BLUE_FILE_ATTRIBUTE_DIRECTORY ;
      if (lpFindFileData->dwFileAttributes == 0)
	lpFindFileData->dwFileAttributes |= BLUE_FILE_ATTRIBUTE_NORMAL ;
      if (dName[0] == '.')
	lpFindFileData->dwFileAttributes |= BLUE_FILE_ATTRIBUTE_HIDDEN ;
      /*
       * Next is create time
       */
      EpochTimeToFileTime (sb.st_mtimespec.tv_sec, 
			   sb.st_mtimespec.tv_nsec,
			   &lpFindFileData->ftCreateTime) ;
      EpochTimeToFileTime (sb.st_atimespec.tv_sec,
			   sb.st_atimespec.tv_nsec, 
			   &lpFindFileData->ftLastAccessTime) ;
      EpochTimeToFileTime (sb.st_ctimespec.tv_sec,
			   sb.st_ctimespec.tv_nsec, 
			   &lpFindFileData->ftLastWriteTime) ;
      lpFindFileData->nFileSizeHigh = sb.st_size >> 32 ;
      lpFindFileData->nFileSizeLow = sb.st_size & 0xFFFFFFFF ;

      tcharName = BlueCcstr2tstr (dName) ;
      BlueCtstrncpy (lpFindFileData->cFileName, tcharName, BLUE_MAX_PATH) ;
      BlueHeapFree (tcharName) ;

      lpFindFileData->cAlternateFileName[0] = TCHAR_EOS ;
      ret = BLUE_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}
      
static BLUE_BOOL 
GetWin32FileAttributeData (BLUE_CHAR *asciiName, 
			   BLUE_WIN32_FILE_ATTRIBUTE_DATA *fadata) 
{
  BLUE_BOOL ret ;
  struct stat sb ;
  int status ;

  ret = BLUE_FALSE ;

  status = stat (asciiName, &sb) ;
  if (status == -1)
    {
      /*
       * See if it's a link.  If so, we still want to show it.  The reason
       * we use stat rather then lstat initially is we do want the 
       * target of the link.  We only want to revert to the link when 
       * the target returns an error.
       */
      status = lstat (asciiName, &sb) ;
    }

  if (status >= 0)
    {
      fadata->dwFileAttributes = 0 ;
      /*
       * We do not support hidden files or System Files or Archive Files
       * or temporary or sparse or compressed,or offline, or encrypted,
       * or virtual
       */
      if (sb.st_flags & UF_IMMUTABLE)
	fadata->dwFileAttributes |= BLUE_FILE_ATTRIBUTE_READONLY ;
      if (sb.st_mode & S_IFDIR)
	{
	  fadata->dwFileAttributes |= BLUE_FILE_ATTRIBUTE_DIRECTORY ;
	}
      if (fadata->dwFileAttributes == 0)
	fadata->dwFileAttributes |= BLUE_FILE_ATTRIBUTE_NORMAL ;
      /*
       * Next is create time
       * Can't believe we don't have a create time, but it looks like we
       * only have last access, modification, and status change
       */
      EpochTimeToFileTime (sb.st_mtimespec.tv_sec,
			   sb.st_mtimespec.tv_nsec, &fadata->ftCreateTime) ;
      EpochTimeToFileTime (sb.st_atimespec.tv_sec,
			   sb.st_mtimespec.tv_nsec,
			   &fadata->ftLastAccessTime) ;
      EpochTimeToFileTime (sb.st_ctimespec.tv_sec,
			   sb.st_ctimespec.tv_nsec,
			   &fadata->ftLastWriteTime) ;
      fadata->nFileSizeHigh = sb.st_size >> 32 ;
      fadata->nFileSizeLow = sb.st_size & 0xFFFFFFFF ;

      ret = BLUE_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(errno)) ;
    }
  return (ret) ;
}

static BLUE_BOOL GetWin32FileBasicInfo (int fd, 
					BLUE_CHAR *name,
					BLUE_FILE_BASIC_INFO *lpFileInformation)
{
  BLUE_BOOL ret ;
  BLUE_FILETIME filetime;
  struct stat sb ;
  int status ;

  ret = BLUE_FALSE ;

  if (fd == -1)
    {
      status = stat (name, &sb) ;
      if (status == -1)
	{
	  /*
	   * See if it's a link.  If so, we still want to show it.  The reason
	   * we use stat rather then lstat initially is we do want the 
	   * target of the link.  We only want to revert to the link when 
	   * the target returns an error.
	   */
	  status = lstat (name, &sb) ;
	}
    }
  else
    {
      status = fstat (fd, &sb) ;
    }

  if (status >= 0)
    {
      EpochTimeToFileTime (sb.st_mtimespec.tv_sec,
			   sb.st_mtimespec.tv_nsec, &filetime) ;
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInformation->CreationTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(BLUE_LARGE_INTEGER) filetime.dwLowDateTime ;
      lpFileInformation->LastWriteTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(BLUE_LARGE_INTEGER) filetime.dwLowDateTime ;
#else
      lpFileInformation->CreationTime.high = filetime.dwHighDateTime ;
      lpFileInformation->CreationTime.low = filetime.dwLowDateTime ;
      lpFileInformation->LastWriteTime.high = filetime.dwHighDateTime ;
      lpFileInformation->LastWriteTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_atimespec.tv_sec,
			   sb.st_atimespec.tv_nsec, &filetime) ;
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInformation->LastAccessTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(BLUE_LARGE_INTEGER) filetime.dwLowDateTime ;
#else
      lpFileInformation->LastAccessTime.high = filetime.dwHighDateTime ;
      lpFileInformation->LastAccessTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_ctimespec.tv_sec,
			   sb.st_ctimespec.tv_nsec, &filetime) ;
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInformation->ChangeTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	filetime.dwLowDateTime ;
#else
      lpFileInformation->ChangeTime.high = filetime.dwHighDateTime ;
      lpFileInformation->ChangeTime.low = filetime.dwLowDateTime ;
#endif
      lpFileInformation->FileAttributes = 0 ;
      /*
       * We do not support hidden files or System Files or Archive Files
       * or temporary or sparse or compressed,or offline, or encrypted,
       * or virtual
       */
      if (sb.st_flags & UF_IMMUTABLE)
	lpFileInformation->FileAttributes |= BLUE_FILE_ATTRIBUTE_READONLY ;
      if (sb.st_mode & S_IFDIR)
	lpFileInformation->FileAttributes |= BLUE_FILE_ATTRIBUTE_DIRECTORY ;
      if (lpFileInformation->FileAttributes == 0)
	lpFileInformation->FileAttributes |= BLUE_FILE_ATTRIBUTE_NORMAL ;
      ret = BLUE_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}

static BLUE_BOOL GetWin32FileInternalInfo (int fd, 
					   BLUE_CHAR *name,
					   BLUE_FILE_INTERNAL_INFO *lpFileInformation)
{
  BLUE_BOOL ret ;

  ret = BLUE_TRUE ;

  lpFileInformation->IndexNumber = 0L ;


  return (ret) ;
}

static BLUE_BOOL GetWin32FileNetworkOpenInfo (int fd, 
					      BLUE_CHAR *name,
					      BLUE_FILE_NETWORK_OPEN_INFO *lpFileInformation)
{
  BLUE_BOOL ret ;
  BLUE_FILETIME filetime;
  struct stat sb ;
  int status ;

  ret = BLUE_FALSE ;

  if (fd == -1)
    {
      status = stat (name, &sb) ;
      if (status == -1)
	{
	  /*
	   * See if it's a link.  If so, we still want to show it.  The reason
	   * we use stat rather then lstat initially is we do want the 
	   * target of the link.  We only want to revert to the link when 
	   * the target returns an error.
	   */
	  status = lstat (name, &sb) ;
	}
    }
  else
    {
      status = fstat (fd, &sb) ;
    }

  if (status >= 0)
    {
      EpochTimeToFileTime (sb.st_mtimespec.tv_sec,
			   sb.st_mtimespec.tv_nsec, &filetime) ;
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInformation->CreationTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(BLUE_LARGE_INTEGER) filetime.dwLowDateTime ;
      lpFileInformation->LastWriteTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(BLUE_LARGE_INTEGER) filetime.dwLowDateTime ;
#else
      lpFileInformation->CreationTime.high = filetime.dwHighDateTime ;
      lpFileInformation->CreationTime.low = filetime.dwLowDateTime ;
      lpFileInformation->LastWriteTime.high = filetime.dwHighDateTime ;
      lpFileInformation->LastWriteTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_atimespec.tv_sec,
			   sb.st_atimespec.tv_nsec, &filetime) ;
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInformation->LastAccessTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(BLUE_LARGE_INTEGER) filetime.dwLowDateTime ;
#else
      lpFileInformation->LastAccessTime.high = filetime.dwHighDateTime ;
      lpFileInformation->LastAccessTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_ctimespec.tv_sec,
			   sb.st_ctimespec.tv_nsec, &filetime) ;
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInformation->ChangeTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	filetime.dwLowDateTime ;
#else
      lpFileInformation->ChangeTime.high = filetime.dwHighDateTime ;
      lpFileInformation->ChangeTime.low = filetime.dwLowDateTime ;
#endif
      lpFileInformation->FileAttributes = 0 ;
      /*
       * We do not support hidden files or System Files or Archive Files
       * or temporary or sparse or compressed,or offline, or encrypted,
       * or virtual
       */
      if (sb.st_flags & UF_IMMUTABLE)
	lpFileInformation->FileAttributes |= BLUE_FILE_ATTRIBUTE_READONLY ;
      if (sb.st_mode & S_IFDIR)
	lpFileInformation->FileAttributes |= BLUE_FILE_ATTRIBUTE_DIRECTORY ;
      if (lpFileInformation->FileAttributes == 0)
	lpFileInformation->FileAttributes |= BLUE_FILE_ATTRIBUTE_NORMAL ;
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInformation->AllocationSize = 
	sb.st_blocks * BLUE_FS_DARWIN_BLOCK_SIZE ;
      lpFileInformation->EndOfFile = sb.st_size ;
#else
      lpFileInformation->AllocationSize.low = 
	sb.st_blocks * BLUE_FS_DARWIN_BLOCK_SIZE ;
      lpFileInformation->EndOfFile.low = sb.st_size ;
      lpFileInformation->AllocationSize.high = 0 ;
      lpFileInformation->EndOfFile.high = 0 ;
#endif      
      ret = BLUE_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}

static BLUE_BOOL 
GetWin32FileStandardInfo (int fd, 
			  BLUE_CHAR *name,
			  BLUE_FILE_STANDARD_INFO *lpFileInformation,
			  BLUE_BOOL delete_pending)
{
  BLUE_BOOL ret ;
  struct stat sb ;
  int status ;

  ret = BLUE_FALSE ;

  if (fd == -1)
    {
      status = stat (name, &sb) ;
      if (status == -1)
	{
	  /*
	   * See if it's a link.  If so, we still want to show it.  The reason
	   * we use stat rather then lstat initially is we do want the 
	   * target of the link.  We only want to revert to the link when 
	   * the target returns an error.
	   */
	  status = lstat (name, &sb) ;
	}
    }
  else
    {
      status = fstat (fd, &sb) ;
    }

  if (status >= 0)
    {
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInformation->AllocationSize = 
	sb.st_blocks * BLUE_FS_DARWIN_BLOCK_SIZE ;
      lpFileInformation->EndOfFile = sb.st_size ;
#else
      lpFileInformation->AllocationSize.low = 
	sb.st_blocks * BLUE_FS_DARWIN_BLOCK_SIZE ;
      lpFileInformation->EndOfFile.low = sb.st_size ;
      lpFileInformation->AllocationSize.high = 0 ;
      lpFileInformation->EndOfFile.high = 0 ;
#endif      
      lpFileInformation->NumberOfLinks = sb.st_nlink ;
      lpFileInformation->DeletePending = delete_pending ;
      lpFileInformation->Directory = BLUE_FALSE ;
      if (sb.st_mode & S_IFDIR)
	lpFileInformation->Directory = BLUE_TRUE ;
      ret = BLUE_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}

static BLUE_BOOL GetWin32FileNameInfo (int fd,
				       BLUE_CHAR *name,
				       BLUE_FILE_NAME_INFO *lpFileInformation,
				       BLUE_DWORD dwBufferSize)
{
  BLUE_TCHAR *tcharName ;

  tcharName = BlueCcstr2tstr (name) ;
  lpFileInformation->FileNameLength = (BLUE_DWORD) BlueCtstrlen (tcharName) *
    sizeof (BLUE_TCHAR) ;
  BlueCmemcpy (lpFileInformation->FileName, tcharName,
	       BLUE_C_MIN (dwBufferSize - sizeof (BLUE_DWORD),
			   lpFileInformation->FileNameLength)) ;
  BlueHeapFree (tcharName) ;
  return (BLUE_TRUE) ;
}


static BLUE_BOOL 
GetWin32FileIdBothDirInfo (int fd,
			   BLUE_CHAR *name,
			   BLUE_FILE_ID_BOTH_DIR_INFO *lpFileInfo,
			   BLUE_DWORD dwBufferSize)
{
  BLUE_BOOL ret ;
  struct stat sb ;
  int status ;
  BLUE_TCHAR *tcharName ;
  BLUE_FILETIME filetime ;

  ret = BLUE_FALSE ;

  if (fd == -1)
    {
      status = stat (name, &sb) ;
      if (status == -1)
	{
	  /*
	   * See if it's a link.  If so, we still want to show it.  The reason
	   * we use stat rather then lstat initially is we do want the 
	   * target of the link.  We only want to revert to the link when 
	   * the target returns an error.
	   */
	  status = lstat (name, &sb) ;
	}
    }
  else
    {
      status = fstat (fd, &sb) ;
    }

  if (status >= 0)
    {
      lpFileInfo->NextEntryOffset = 0 ;
      /*
       * This isn't right, but it's probably the closest we can do
       */
      lpFileInfo->FileIndex = 0 ;
      EpochTimeToFileTime (sb.st_mtimespec.tv_sec,
			   sb.st_mtimespec.tv_nsec, &filetime) ;
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInfo->CreationTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	filetime.dwLowDateTime ;
      lpFileInfo->LastWriteTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	filetime.dwLowDateTime ;
#else
      lpFileInfo->CreationTime.high = filetime.dwHighDateTime ;
      lpFileInfo->CreationTime.low = filetime.dwLowDateTime ;
      lpFileInfo->LastWriteTime.high = filetime.dwHighDateTime ;
      lpFileInfo->LastWriteTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_atimespec.tv_sec,
			   sb.st_atimespec.tv_nsec, &filetime) ;
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInfo->LastAccessTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	filetime.dwLowDateTime ;
#else
      lpFileInfo->LastAccessTime.high = filetime.dwHighDateTime ;
      lpFileInfo->LastAccessTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_ctimespec.tv_sec,
			   sb.st_ctimespec.tv_nsec, &filetime) ;
#if defined(BLUE_PARAM_64BIT_INTEGER)
      lpFileInfo->ChangeTime = 
	((BLUE_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	filetime.dwLowDateTime ;
      lpFileInfo->EndOfFile = sb.st_size ;
      lpFileInfo->AllocationSize = 
	sb.st_blocks * BLUE_FS_DARWIN_BLOCK_SIZE ;
#else
      lpFileInfo->ChangeTime.high = filetime.dwHighDateTime ;
      lpFileInfo->ChangeTime.low = filetime.dwLowDateTime ;
      lpFileInfo->EndOfFile.low = sb.st_size ;
      lpFileInfo->EndOfFile.high = 0 ;
      lpFileInfo->AllocationSize.low = 
	sb.st_blocks * BLUE_FS_DARWIN_BLOCK_SIZE ;
      lpFileInfo->AllocationSize.high = 0 ;
#endif
      lpFileInfo->FileAttributes = 0 ;
      /*
       * We do not support hidden files or System Files or Archive Files
       * or temporary or sparse or compressed,or offline, or encrypted,
       * or virtual
       */
      if (sb.st_flags & UF_IMMUTABLE)
	lpFileInfo->FileAttributes |= BLUE_FILE_ATTRIBUTE_READONLY ;
      if (sb.st_mode & S_IFDIR)
	lpFileInfo->FileAttributes |= BLUE_FILE_ATTRIBUTE_DIRECTORY ;
      if (lpFileInfo->FileAttributes == 0)
	lpFileInfo->FileAttributes |= BLUE_FILE_ATTRIBUTE_NORMAL ;

      tcharName = BlueCcstr2tstr (name) ;
      lpFileInfo->FileNameLength = (BLUE_DWORD) BlueCtstrlen (tcharName) *
	sizeof (BLUE_TCHAR) ;
      lpFileInfo->EaSize = 0 ;
      lpFileInfo->ShortNameLength = 0 ;
      lpFileInfo->ShortName[0] = TCHAR_EOS ;
      lpFileInfo->FileId = 0 ;
      BlueCmemcpy (lpFileInfo->FileName, tcharName,
		   BLUE_C_MIN (dwBufferSize - 
			       sizeof (BLUE_FILE_ID_BOTH_DIR_INFO) - 
			       sizeof (BLUE_TCHAR),
			       lpFileInfo->FileNameLength)) ;
      BlueHeapFree (tcharName) ;
      ret = BLUE_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}

static BLUE_HANDLE 
BlueFSDarwinFindFirstFile (BLUE_LPCTSTR lpFileName,
			  BLUE_LPWIN32_FIND_DATAW lpFindFileData,
			  BLUE_BOOL *more) 
{
  BLUE_HANDLE hRet ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  BLUE_CHAR *asciiName ;
  BLUE_TCHAR *tcharName ;
  struct dirent *dirent ;
  BLUE_CHAR *pathname ;
  BLUE_SIZET len ;
  BLUE_PATH *path ;
  BLUE_LPTSTR cursor ;
  BLUE_LPCTSTR filename ;

  context = BlueHeapMalloc (sizeof (BLUE_FS_DARWIN_CONTEXT)) ;

  hRet = BLUE_INVALID_HANDLE_VALUE ;
  if (context != BLUE_NULL)
    {
      context->pattern = BLUE_NULL ;

      path = BluePathCreateW (lpFileName) ;
      filename = BluePathFilename (path) ;
      if (filename != BLUE_NULL)
	{
	  context->pattern = BlueCtstr2cstr(filename) ;
	  BluePathFreeFilename (path) ;
	}

      BluePathSetType (path, BLUE_FS_DARWIN) ;
      len = 0 ;
      len = BluePathPrintW (path, NULL, &len) + 1 ;
      tcharName = BlueHeapMalloc (len * sizeof (BLUE_TCHAR)) ;
      cursor = tcharName ;
      BluePathPrintW (path, &cursor, &len) ;
      BluePathDelete (path) ;

      asciiName = FilePath2DarwinPath (tcharName) ;
      BlueHeapFree (tcharName) ;
      context->name = BlueCstrdup (asciiName) ;
      context->dir = opendir (asciiName) ;
      BlueHeapFree (asciiName) ;
      if (context->dir != NULL)
	{
	  for (dirent = readdir (context->dir) ;
	       dirent != NULL && 
		 !BlueFileMatch (context->pattern, dirent->d_name,
				 BLUE_FILE_MATCH_PATHNAME |
				 BLUE_FILE_MATCH_CASEFOLD) ;
	       dirent = readdir (context->dir) ) ;

	  if (dirent == NULL)
	    {
	      closedir (context->dir) ;
	      context->dir = NULL ;
	    }
	  else
	    {
	      /*
	       * Let's return the info
	       */
	      len = BlueCstrlen(context->name) + BlueCstrlen (dirent->d_name) ;
	      pathname = BlueHeapMalloc (len+2) ;
	      BlueCsnprintf (pathname, len+2, "%s/%s", 
			     context->name, dirent->d_name) ;
	      GetWin32FindFileData (pathname, dirent->d_name, lpFindFileData) ;
	      BlueHeapFree (pathname) ;

	      *more = BLUE_FALSE ;

	      for (context->nextRet = readdir_r (context->dir,
						 &context->nextDirent,
						 &dirent) ;
		   dirent != NULL && 
		     !BlueFileMatch (context->pattern, dirent->d_name,
				     BLUE_FILE_MATCH_PATHNAME |
				     BLUE_FILE_MATCH_CASEFOLD) ;
		   context->nextRet = readdir_r (context->dir,
						 &context->nextDirent,
						 &dirent) ) ;

	      if (dirent != NULL)
		*more = BLUE_TRUE ;
	      else
		{
		  context->nextRet = 1 ;
		}
	    }
	}

      if (context->dir == NULL)
	{
	  BlueThreadSetVariable (BlueLastError, 
				 (BLUE_DWORD_PTR) TranslateError(errno)) ;
	  BlueHeapFree (context->name) ;
	  if (context->pattern != NULL)
	    BlueHeapFree (context->pattern) ;
	  BlueHeapFree (context) ;
	}
      else
	hRet = BlueHandleCreate (BLUE_HANDLE_FSWIN32_FILE, context) ;
    }

  return (hRet) ;
}

static BLUE_BOOL 
BlueFSDarwinFindNextFile (BLUE_HANDLE hFindFile,
			  BLUE_LPWIN32_FIND_DATAW lpFindFileData,
			  BLUE_BOOL *more) 
{
  struct dirent *dirent ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  BLUE_BOOL ret ;
  BLUE_CHAR *pathname ;
  BLUE_SIZET len ;

  ret = BLUE_FALSE ;
  *more = BLUE_FALSE ;
  context = BlueHandleLock (hFindFile) ;

  if (context == BLUE_NULL)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      if (context->nextRet == 0)
	{
	  ret = BLUE_TRUE ;
	  len = BlueCstrlen(context->name) + 
	    BlueCstrlen (context->nextDirent.d_name) ;
	  pathname = BlueHeapMalloc (len+2) ;
	  BlueCsnprintf (pathname, len+2, "%s/%s", 
			 context->name, 
			 context->nextDirent.d_name) ;
	  ret = GetWin32FindFileData (pathname, context->nextDirent.d_name,
				      lpFindFileData) ;
	  BlueHeapFree (pathname) ;

	  if (ret == BLUE_TRUE)
	    {
	      for (context->nextRet = readdir_r (context->dir,
						 &context->nextDirent,
						 &dirent) ;
		   dirent != NULL && 
		     !BlueFileMatch (context->pattern, dirent->d_name,
				     BLUE_FILE_MATCH_PATHNAME |
				     BLUE_FILE_MATCH_CASEFOLD) ;
		   context->nextRet = readdir_r (context->dir,
						 &context->nextDirent,
						 &dirent) ) ;

	      if (dirent != NULL)
		*more = BLUE_TRUE ;
	      else
		{
		  context->nextRet = 1 ;
		}
	    }
	}
      else if (context->nextRet == 1)
	BlueThreadSetVariable (BlueLastError, (BLUE_DWORD_PTR)
			       BLUE_ERROR_NO_MORE_FILES) ;
      else
	BlueThreadSetVariable (BlueLastError, 
			       (BLUE_DWORD_PTR) TranslateError(errno)) ;

      BlueHandleUnlock (hFindFile) ;
    }

  return (ret) ;
}

static BLUE_BOOL BlueFSDarwinFindClose (BLUE_HANDLE hFindFile) 
{
  BLUE_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  int status ;

  ret = BLUE_FALSE ;
  context = BlueHandleLock (hFindFile) ;

  if (context == BLUE_NULL)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      status = closedir (context->dir) ;
      if (status == 0)
	{
	  ret = BLUE_TRUE ;
	  BlueHandleDestroy (hFindFile) ;
	  BlueHeapFree (context->name) ;
	  if (context->pattern != BLUE_NULL)
	    BlueHeapFree (context->pattern) ;
	  BlueHeapFree (context) ;
	}
      else
	BlueThreadSetVariable (BlueLastError, 
			       (BLUE_DWORD_PTR) TranslateError(errno)) ;

      BlueHandleUnlock (hFindFile) ;
    }

  return (ret) ;
}

static BLUE_BOOL BlueFSDarwinFlushFileBuffers (BLUE_HANDLE hFile) 
{
  /*
   * No flush needed
   */
  return (BLUE_TRUE) ;
}

static BLUE_BOOL 
BlueFSDarwinGetFileAttributesEx (BLUE_LPCTSTR lpFileName,
				BLUE_GET_FILEEX_INFO_LEVELS fInfoLevelId,
				BLUE_LPVOID lpFileInformation) 
{
  BLUE_BOOL ret ;
  BLUE_CHAR *asciiName ;

  ret = BLUE_FALSE ;
  /*
   * This is the only one we support
   */
  if (fInfoLevelId == BlueGetFileExInfoStandard)
    {
      asciiName = FilePath2DarwinPath (lpFileName) ;
      ret = GetWin32FileAttributeData (asciiName, lpFileInformation) ;
      BlueHeapFree (asciiName) ;
    }
  return (ret) ;
}

static BLUE_BOOL 
BlueFSDarwinGetFileInformationByHandleEx 
(BLUE_HANDLE hFile,
 BLUE_FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
 BLUE_LPVOID lpFileInformation,
 BLUE_DWORD dwBufferSize) 
{
  BLUE_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;

  ret = BLUE_FALSE ;

  context = BlueHandleLock (hFile) ;
  if (context == BLUE_NULL)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      switch (FileInformationClass)
	{
	case BlueFileNetworkOpenInfo:
	  if (dwBufferSize >= sizeof (BLUE_FILE_NETWORK_OPEN_INFO))
	    {
	      ret = GetWin32FileNetworkOpenInfo (context->fd, 
						 context->name,
						 lpFileInformation) ;
	    }
	  break ;

	case BlueFileInternalInformation:
	  if (dwBufferSize >= sizeof (BLUE_FILE_INTERNAL_INFO))
	    {
	      ret = GetWin32FileInternalInfo (context->fd,
					      context->name,
					      lpFileInformation) ;
	    }
	  break ;

	case BlueFileBasicInfo:
	  if (dwBufferSize >= sizeof (BLUE_FILE_BASIC_INFO))
	    {
	      ret = GetWin32FileBasicInfo (context->fd, 
					   context->name,
					   lpFileInformation) ;
	    }
	  break ;

	case BlueFileStandardInfo:
	  if (dwBufferSize >= sizeof (BLUE_FILE_STANDARD_INFO))
	    {
	      ret = GetWin32FileStandardInfo (context->fd, 
					      context->name,
					      lpFileInformation,
					      context->deleteOnClose) ;
	    }
	  break ;

	case BlueFileNameInfo:
	  if (dwBufferSize >= sizeof (BLUE_FILE_NAME_INFO) - sizeof(BLUE_WCHAR))
	    {
	      ret = GetWin32FileNameInfo (context->fd, context->name,
					  lpFileInformation, 
					  dwBufferSize) ;
	    }
	  break ;

	case BlueFileEndOfFileInfo:
	case BlueFileRenameInfo:
	case BlueFileDispositionInfo:
	case BlueFileAllocationInfo:
	case BlueFileInfoStandard:
	  /*
	   * These are for sets. They don't apply for get
	   */
	  break ;

	default:
	case BlueFileStreamInfo:
	case BlueFileCompressionInfo:
	case BlueFileAttributeTagInfo:
	case BlueFileIdBothDirectoryRestartInfo:
	  /*
	   * These are not supported
	   */
	  break ;

	case BlueFileIdBothDirectoryInfo:
	  if (dwBufferSize >= sizeof (BLUE_FILE_ID_BOTH_DIR_INFO) - 
	      sizeof (BLUE_WCHAR))
	    {
	      ret = GetWin32FileIdBothDirInfo (context->fd, context->name,
					       lpFileInformation, 
					       dwBufferSize) ;
	    }
	  break ;

	case BlueFileAllInfo:
	  if (dwBufferSize >= sizeof (BLUE_FILE_ALL_INFO) - 
	      sizeof (BLUE_WCHAR))
	    {
	      BLUE_FILE_ALL_INFO *lpAllInformation =
		(BLUE_FILE_ALL_INFO *) lpFileInformation ;

	      ret = GetWin32FileBasicInfo (context->fd, 
					   context->name,
					   &lpAllInformation->BasicInfo) ;
	      if (ret)
		{
		  ret = GetWin32FileStandardInfo (context->fd, 
						  context->name,
						  &lpAllInformation->StandardInfo,
						  context->deleteOnClose) ;
		}
	      if (ret)
		{
		  ret = GetWin32FileInternalInfo (context->fd,
						  context->name,
						  &lpAllInformation->InternalInfo) ;
		}
	      if (ret)
		{
		  lpAllInformation->EAInfo.EaSize = 0 ;
		  if (lpAllInformation->BasicInfo.FileAttributes &
		      BLUE_FILE_ATTRIBUTE_DIRECTORY)
		    {
		      lpAllInformation->AccessInfo.AccessFlags =
			BLUE_FILE_LIST_DIRECTORY |
			BLUE_FILE_ADD_FILE |
			BLUE_FILE_ADD_SUBDIRECTORY |
			BLUE_FILE_DELETE_CHILD |
			BLUE_FILE_READ_ATTRIBUTES |
			BLUE_FILE_WRITE_ATTRIBUTES |
			BLUE_DELETE ;
		    }
		  else
		    {
		      lpAllInformation->AccessInfo.AccessFlags =
			BLUE_FILE_READ_DATA |
			BLUE_FILE_WRITE_DATA |
			BLUE_FILE_APPEND_DATA |
			BLUE_FILE_EXECUTE |
			BLUE_FILE_READ_ATTRIBUTES |
			BLUE_FILE_WRITE_ATTRIBUTES |
			BLUE_DELETE ;
		    }
		  lpAllInformation->PositionInfo.CurrentByteOffset = 0 ;
		  lpAllInformation->ModeInfo.Mode = 0 ;
		  lpAllInformation->AlignmentInfo.AlignmentRequirement = 0 ;
		}
	      if (ret)
		{
		  ret = GetWin32FileNameInfo (context->fd,
					      context->name,
					      &lpAllInformation->NameInfo,
					      dwBufferSize -
					      sizeof (BLUE_FILE_ALL_INFO)) ;
		}
	    }
	  break ;
	}
      BlueHandleUnlock (hFile) ;
    }

  return (ret) ;
}

static BLUE_BOOL BlueFSDarwinMoveFile (BLUE_LPCTSTR lpExistingFileName,
				      BLUE_LPCTSTR lpNewFileName) 
{
  BLUE_BOOL ret ;
  int status ;

  BLUE_CHAR *asciiExisting ;
  BLUE_CHAR *asciiNew ;

  ret = BLUE_TRUE ;
  asciiExisting = FilePath2DarwinPath (lpExistingFileName) ;
  asciiNew = FilePath2DarwinPath (lpNewFileName) ;

  status = rename (asciiExisting, asciiNew) ;
  BlueHeapFree (asciiExisting);
  BlueHeapFree (asciiNew) ;

  if (status < 0)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(errno)) ;
      ret = BLUE_FALSE ;
    }

  return (ret) ;
}

BLUE_HANDLE BlueFSDarwinGetOverlappedEvent (BLUE_HANDLE hOverlapped)
{
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;
  BLUE_HANDLE hRet ;

  hRet = BLUE_HANDLE_NULL ;
  Overlapped = BlueHandleLock (hOverlapped) ;
  if (Overlapped != BLUE_NULL)
    {
      hRet = Overlapped->hEvent ;
      BlueHandleUnlock (hOverlapped) ;
    }
  return (hRet) ;
}

static BLUE_HANDLE BlueFSDarwinCreateOverlapped (BLUE_VOID)
{
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;
  BLUE_HANDLE hRet ;

  hRet = BLUE_HANDLE_NULL ;

  hRet = (BLUE_HANDLE) BlueQdequeue (BlueFSDarwinAIOFreeQ) ;
  if (hRet == BLUE_HANDLE_NULL)
    {
      Overlapped = BlueHeapMalloc (sizeof (BLUE_FSDARWIN_OVERLAPPED)) ;
      if (Overlapped != BLUE_NULL)
	{
	  hRet = BlueHandleCreate (BLUE_HANDLE_FSDARWIN_OVERLAPPED, 
				   Overlapped) ;
	  Overlapped->offset = 0 ;
	  Overlapped->hEvent = BlueEventCreate (BLUE_EVENT_MANUAL) ;
	  Overlapped->hBusy = BlueEventCreate (BLUE_EVENT_AUTO) ;

	  Overlapped->hThread = BlueThreadCreate (&BlueFSDarwinAIOThread,
						  BLUE_THREAD_AIO,
						  g_instance++,
						  Overlapped,
						  BLUE_THREAD_JOIN,
						  BLUE_HANDLE_NULL) ;
	}
    }

  if (hRet != BLUE_HANDLE_NULL)
    {
      Overlapped = BlueHandleLock (hRet) ;
      if (Overlapped != BLUE_NULL)
	{
	  Overlapped->Errno = 0 ;
	  BlueHandleUnlock (hRet) ;
	}
    }
  return (hRet) ;
}

BLUE_VOID BlueFSDarwinDestroyOverlapped (BLUE_HANDLE hOverlapped)
{
  BlueQenqueue (BlueFSDarwinAIOFreeQ, (BLUE_VOID *) hOverlapped) ;
}

BLUE_VOID BlueFSDarwinSetOverlappedOffset (BLUE_HANDLE hOverlapped,
					   BLUE_OFFT offset)
{
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;

  Overlapped = BlueHandleLock (hOverlapped) ;
  if (Overlapped != BLUE_NULL)
    {
      Overlapped->offset = offset ;
      BlueHandleUnlock (hOverlapped) ;
    }
}

static BLUE_BOOL 
BlueFSDarwinGetOverlappedResult (BLUE_HANDLE hFile,
				BLUE_HANDLE hOverlapped,
				BLUE_LPDWORD lpNumberOfBytesTransferred,
				BLUE_BOOL bWait) 
{
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  BLUE_BOOL ret ;

  ret = BLUE_FALSE ;
  context = BlueHandleLock (hFile) ;

  if (context == BLUE_NULL || context->backup)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      Overlapped = BlueHandleLock (hOverlapped) ;
      if (Overlapped != BLUE_NULL)
	{
	  if (bWait)
	    BlueEventWait (Overlapped->hEvent) ;

	  if (BlueEventTest (Overlapped->hEvent))
	    {
	      if (Overlapped->dwResult < 0)
		{
		  BlueThreadSetVariable (BlueLastError, 
					 (BLUE_DWORD_PTR) 
					 TranslateError(Overlapped->Errno)) ;
		}
	      else
		{
		  *lpNumberOfBytesTransferred = Overlapped->dwResult ;
		  ret = BLUE_TRUE ;
		}
	    }
	  else
	    {
	      BlueThreadSetVariable (BlueLastError, 
				     (BLUE_DWORD_PTR) 
				     TranslateError(EINPROGRESS)) ;
	    }
	  BlueHandleUnlock (hOverlapped) ;
	}
    }

  if (context != BLUE_NULL)
    BlueHandleUnlock (hFile) ;

  return (ret) ;
}

static BLUE_BOOL BlueFSDarwinSetEndOfFile (BLUE_HANDLE hFile) 
{
  BLUE_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  off_t offset ;
  int status ;

  ret = BLUE_FALSE ;
  context = BlueHandleLock (hFile) ;

  if (context == BLUE_NULL || context->backup)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      /*
       * Get current offset
       */
      offset = lseek (context->fd, 0, SEEK_CUR) ;
      if (offset >= 0)
	{
	  status = ftruncate (context->fd, offset) ;
	  if (status == 0)
	    ret = BLUE_TRUE ;
	  else
	    BlueThreadSetVariable (BlueLastError, 
				   (BLUE_DWORD_PTR) TranslateError(errno)) ;
	}
      else
	BlueThreadSetVariable (BlueLastError, 
			       (BLUE_DWORD_PTR) TranslateError(errno)) ;
    }

  if (context != BLUE_NULL)
    BlueHandleUnlock (hFile) ;

  return (ret) ;
}

static BLUE_BOOL BlueFSDarwinSetFileAttributes (BLUE_LPCTSTR lpFileName,
					       BLUE_DWORD dwFileAttributes)
{
  BLUE_BOOL ret ;

  /*
   * We can't set file attributes on Darwin
   */
  ret = BLUE_TRUE ;

  return (ret) ;
}

static BLUE_BOOL 
BlueFSDarwinSetFileInformationByHandle (BLUE_HANDLE hFile,
				       BLUE_FILE_INFO_BY_HANDLE_CLASS
				       FileInformationClass,
				       BLUE_LPVOID lpFileInformation,
				       BLUE_DWORD dwBufferSize) 
{
  BLUE_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;

  ret = BLUE_FALSE ;
  context = BlueHandleLock (hFile) ;

  if (context == BLUE_NULL)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      switch (FileInformationClass)
	{
	case BlueFileBasicInfo:
	  ret = BLUE_TRUE;
	  break ;
	  
	default:
	  break ;

	case BlueFileAllocationInfo:
	  {
	    BLUE_FILE_ALLOCATION_INFO *info ;
	    off_t offset ;

	    if (lpFileInformation != BLUE_NULL)
	      {
		info = lpFileInformation ;

		offset = (off_t) info->AllocationSize ;
		if (ftruncate (context->fd, offset) == 0)
		  ret = BLUE_TRUE ;
		else
		  BlueThreadSetVariable (BlueLastError, 
					 (BLUE_DWORD_PTR) 
					 TranslateError(errno)) ;
	      }
	  }
	  break ;

	case BlueFileRenameInfo:
	  {
	    BLUE_FILE_RENAME_INFO *rename_info ;
	    BLUE_TCHAR *to_name ;
	    BLUE_CHAR *sztoname ;
	    int status ;
	    BLUE_CHAR *p ;

	    if (lpFileInformation != BLUE_NULL)
	      {
		rename_info = lpFileInformation ;

		/* get the to name */
		to_name = BlueHeapMalloc (rename_info->FileNameLength +
					  sizeof (BLUE_TCHAR)) ;
		BlueCtstrncpy (to_name, rename_info->FileName,
			       (rename_info->FileNameLength /
				sizeof(BLUE_TCHAR))) ;
		to_name[rename_info->FileNameLength / sizeof (BLUE_TCHAR)] =
		  TCHAR_EOS ;
		
		sztoname = BlueCtstr2cstr (to_name) ;
		/* convert \\ to / */
		for (p = sztoname ; *p != '\0' ; p++)
		  if (*p == '\\')
		    *p = '/' ;

		if (rename_info->ReplaceIfExists)
		  {
		    /*
		     * Try to remove the target (don't care what it is)
		     * and don't care if it fails
		     */
		    rmdir (sztoname) ;
		    unlink (sztoname) ;
		  }

		status = rename (context->name, sztoname) ;
		BlueHeapFree (context->name) ;
		context->name = sztoname ;

		BlueHeapFree (to_name) ;
		
		if (status == 0)
		  ret = BLUE_TRUE ;
		else
		  BlueThreadSetVariable 
		    (BlueLastError, 
		     (BLUE_DWORD_PTR) TranslateError(errno)) ;
	      }
	  }
	  break ;

	case BlueFileEndOfFileInfo:
	  {
	    BLUE_FILE_END_OF_FILE_INFO *fileEof ;
	    off_t offset ;
	    int status ;

	    if (lpFileInformation != BLUE_NULL)
	      {
		fileEof = lpFileInformation ;
		offset = (off_t) fileEof->EndOfFile ;
		offset = lseek (context->fd, offset, SEEK_SET) ;
		if (offset >= 0)
		  {
		    status = ftruncate (context->fd, offset) ;
		    if (status == 0)
		      ret = BLUE_TRUE ;
		    else
		      BlueThreadSetVariable (BlueLastError, 
					     (BLUE_DWORD_PTR) 
					     TranslateError(errno)) ;
		  }
		else
		  BlueThreadSetVariable (BlueLastError, 
					 (BLUE_DWORD_PTR) TranslateError(errno)) ;
	      }
	  }
	  break ;

	case BlueFileDispositionInfo:
	  {
	    BLUE_FILE_DISPOSITION_INFO *fileDisposition ;

	    if (lpFileInformation != BLUE_NULL)
	      {
		fileDisposition = lpFileInformation ;

		context->deleteOnClose = fileDisposition->DeleteFile ;
		ret = BLUE_TRUE ;
	      }
	  }
	  break ;
	}
    }

  if (context != BLUE_NULL)
    BlueHandleUnlock (hFile) ;

  return ((BLUE_BOOL) ret) ;
}

static BLUE_DWORD BlueFSDarwinSetFilePointer (BLUE_HANDLE hFile,
					     BLUE_LONG lDistanceToMove,
					     BLUE_PLONG lpDistanceToMoveHigh,
					     BLUE_DWORD dwMoveMethod) 
{
  BLUE_DWORD ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  off_t offset ;
  int whence ;

  ret = BLUE_INVALID_SET_FILE_POINTER ;
  context = BlueHandleLock (hFile) ;

  if (context == BLUE_NULL || context->backup)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      switch (dwMoveMethod)
	{
	default:
	case BLUE_FILE_BEGIN:
	  whence = SEEK_SET ;
	  break ;
	case BLUE_FILE_END:
	  whence = SEEK_END ;
	  break ;
	case BLUE_FILE_CURRENT:
	  whence = SEEK_CUR ;
	  break ;
	}

      offset = lDistanceToMove ;
      if (sizeof (off_t) > sizeof (BLUE_LONG) && 
	  lpDistanceToMoveHigh != BLUE_NULL)
	offset |= (off_t) *lpDistanceToMoveHigh << 32 ;

      offset = lseek (context->fd, offset, whence) ;
      if (offset >= 0)
	ret = (BLUE_DWORD) (offset & 0xFFFFFFFF) ;
      else
	BlueThreadSetVariable (BlueLastError, 
			       (BLUE_DWORD_PTR) TranslateError(errno)) ;

    }

  if (context != BLUE_NULL)
    BlueHandleUnlock (hFile) ;

  return (ret) ;
}

static BLUE_BOOL 
BlueFSDarwinTransactNamedPipe (BLUE_HANDLE hFile,
			      BLUE_LPVOID lpInBuffer,
			      BLUE_DWORD nInBufferSize,
			      BLUE_LPVOID lpOutBuffer,
			      BLUE_DWORD nOutBufferSize,
			      BLUE_LPDWORD lpBytesRead,
			      BLUE_HANDLE hOverlapped)
{
  return (BLUE_FALSE) ;
}

static BLUE_BOOL 
BlueFSDarwinGetDiskFreeSpace (BLUE_LPCTSTR lpRootPathName,
			     BLUE_LPDWORD lpSectorsPerCluster,
			     BLUE_LPDWORD lpBytesPerSector,
			     BLUE_LPDWORD lpNumberOfFreeClusters,
			     BLUE_LPDWORD lpTotalNumberOfClusters) 
{
  BLUE_BOOL ret ;
  struct statfs fsstat ;
  int status ;
  BLUE_CHAR *asciiPath ;

  asciiPath = FilePath2DarwinPath (lpRootPathName) ;
  status = statfs (asciiPath, &fsstat) ;
  BlueHeapFree (asciiPath) ;

  ret = BLUE_FALSE ;
  if (status >= 0)
    {
      ret = BLUE_TRUE ;
      *lpSectorsPerCluster = 1 ;
      *lpBytesPerSector = fsstat.f_bsize ;
      *lpNumberOfFreeClusters = (BLUE_DWORD) fsstat.f_bavail ;
      *lpTotalNumberOfClusters = (BLUE_DWORD) fsstat.f_blocks ;
    }
  else
    BlueThreadSetVariable (BlueLastError, 
			   (BLUE_DWORD_PTR) TranslateError(errno)) ;

  return (ret) ;
}

static BLUE_BOOL
BlueFSDarwinGetVolumeInformation (BLUE_LPCTSTR lpRootPathName,
				 BLUE_LPTSTR lpVolumeNameBuffer,
				 BLUE_DWORD nVolumeNameSize,
				 BLUE_LPDWORD lpVolumeSerialNumber,
				 BLUE_LPDWORD lpMaximumComponentLength,
				 BLUE_LPDWORD lpFileSystemFlags,
				 BLUE_LPTSTR lpFileSystemName,
				 BLUE_DWORD nFileSystemName) 
{
  BLUE_BOOL ret ;
  struct statfs fsstat ;
  int status ;
  BLUE_CHAR *asciiPath ;
  BLUE_LPTSTR tcharPath ;

  asciiPath = FilePath2DarwinPath (lpRootPathName) ;
  status = statfs (asciiPath, &fsstat) ;
  BlueHeapFree (asciiPath) ;

  ret = BLUE_FALSE ;
  if (status >= 0)
    {
      ret = BLUE_TRUE ;
      if (lpFileSystemName != BLUE_NULL)
	{
	  asciiPath = BlueHeapMalloc (MFSNAMELEN+1) ;
	  BlueCstrncpy (asciiPath, fsstat.f_fstypename, MFSNAMELEN) ;
	  asciiPath[MFSNAMELEN] = TCHAR_EOS ;
	  tcharPath = BlueCcstr2tstr (asciiPath) ;
	  BlueCtstrncpy (lpFileSystemName, tcharPath, nFileSystemName) ;
	  BlueHeapFree (tcharPath) ;
	  BlueHeapFree (asciiPath) ;
	}

      if (lpVolumeNameBuffer != BLUE_NULL)
	{
	  asciiPath = BlueHeapMalloc (MNAMELEN+1) ;
	  BlueCstrncpy (asciiPath, fsstat.f_mntfromname, MNAMELEN) ;
	  asciiPath[MNAMELEN] = TCHAR_EOS ;
	  tcharPath = BlueCcstr2tstr (asciiPath) ;
	  BlueCtstrncpy (lpVolumeNameBuffer, tcharPath, nVolumeNameSize) ;
	  BlueHeapFree (tcharPath) ;
	  BlueHeapFree (asciiPath) ;
	}

      if (lpVolumeSerialNumber != BLUE_NULL)
	*lpVolumeSerialNumber = fsstat.f_fsid.val[0] ;

      if (lpMaximumComponentLength != BLUE_NULL)
	*lpMaximumComponentLength = MAXPATHLEN ;

      if (lpFileSystemFlags != BLUE_NULL)
	*lpFileSystemFlags = fsstat.f_flags ;
    }
  else
    BlueThreadSetVariable (BlueLastError, 
			   (BLUE_DWORD_PTR) TranslateError(errno)) ;

  return (ret) ;
}

/**
 * Unlock a region in a file
 * 
 * \param hFile
 * File Handle to unlock 
 *
 * \param length_low
 * the low order 32 bits of the length of the region
 *
 * \param length_high
 * the high order 32 bits of the length of the region
 *
 * \param hOverlapped
 * The overlapped structure which specifies the offset
 *
 * \returns
 * BLUE_TRUE if successful, BLUE_FALSE otherwise
 */
static BLUE_BOOL BlueFSDarwinUnlockFileEx (BLUE_HANDLE hFile, 
					  BLUE_UINT32 length_low, 
					  BLUE_UINT32 length_high,
					  BLUE_HANDLE hOverlapped)
{
  BLUE_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  int status ;

  ret = BLUE_FALSE ;
  context = BlueHandleLock (hFile) ;

  if (context == BLUE_NULL || context->backup)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      status = flock (context->fd, LOCK_UN) ;
      if (status == 0)
	ret = BLUE_TRUE ;
      else
	BlueThreadSetVariable (BlueLastError, 
			       (BLUE_DWORD_PTR) TranslateError(errno)) ;
    }

  if (context != BLUE_NULL)
    BlueHandleUnlock (hFile) ;
  return (ret) ;
 }

/**
 * Lock a region of a file
 * 
 * \param hFile
 * Handle to file to unlock region in 
 *
 * \param flags
 * Flags for lock
 *
 * \param length_low
 * Low order 32 bits of length of region
 *
 * \param length_high
 * High order 32 bits of length of region
 *
 * \param lpOverlapped
 * Pointer to overlapped structure containing offset of region
 *
 * \returns
 * BLUE_TRUE if successful, BLUE_FALSE otherwise
 */
static BLUE_BOOL BlueFSDarwinLockFileEx (BLUE_HANDLE hFile, BLUE_DWORD flags,
					BLUE_DWORD length_low, 
					BLUE_DWORD length_high,
					BLUE_HANDLE lpOverlapped)
{
  BLUE_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  int status ;
  int operation ;

  ret = BLUE_FALSE ;
  context = BlueHandleLock (hFile) ;

  if (context != BLUE_NULL || context->backup)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      if (flags & BLUE_LOCKFILE_EXCLUSIVE_LOCK)
	operation = LOCK_EX ;
      else
	operation = LOCK_SH ;
      if (flags & BLUE_LOCKFILE_FAIL_IMMEDIATELY)
	operation |= LOCK_NB ;

      status = flock (context->fd, operation) ;
      if (status == 0)
	ret = BLUE_TRUE ;
      else
	BlueThreadSetVariable (BlueLastError, 
			       (BLUE_DWORD_PTR) TranslateError(errno)) ;
    }

  if (context != BLUE_NULL)
    BlueHandleUnlock (hFile) ;

  return (ret) ;
}

static BLUE_FILE_FSINFO BlueFSDarwinInfo =
  {
    &BlueFSDarwinCreateFile,
    &BlueFSDarwinDeleteFile,
    &BlueFSDarwinFindFirstFile,
    &BlueFSDarwinFindNextFile,
    &BlueFSDarwinFindClose,
    &BlueFSDarwinFlushFileBuffers,
    &BlueFSDarwinGetFileAttributesEx,
    &BlueFSDarwinGetFileInformationByHandleEx,
    &BlueFSDarwinMoveFile,
    &BlueFSDarwinGetOverlappedResult,
    &BlueFSDarwinCreateOverlapped,
    &BlueFSDarwinDestroyOverlapped,
    &BlueFSDarwinSetOverlappedOffset,
    &BlueFSDarwinSetEndOfFile,
    &BlueFSDarwinSetFileAttributes,
    &BlueFSDarwinSetFileInformationByHandle,
    &BlueFSDarwinSetFilePointer,
    &BlueFSDarwinWriteFile,
    &BlueFSDarwinReadFile,
    &BlueFSDarwinCloseHandle,
    &BlueFSDarwinTransactNamedPipe,
    &BlueFSDarwinGetDiskFreeSpace,
    &BlueFSDarwinGetVolumeInformation,
    &BlueFSDarwinCreateDirectory,
    &BlueFSDarwinRemoveDirectory,
    &BlueFSDarwinUnlockFileEx,
    &BlueFSDarwinLockFileEx,
    BLUE_NULL,
    BLUE_NULL
  } ;

static BLUE_DWORD 
BlueFSDarwinAIOThread (BLUE_HANDLE hThread, BLUE_VOID *context)
{
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;
  
  Overlapped = context ;

  while (!BlueThreadIsDeleting (hThread))
    {
      BlueEventWait (Overlapped->hBusy) ;
      Overlapped->Errno = 0 ;
      if (Overlapped->opcode == BLUE_FSDARWIN_READ)
	{
	  Overlapped->dwResult = 
	    (BLUE_INT) pread (Overlapped->fd,
			      (void *) Overlapped->lpBuffer,
			      Overlapped->nNumberOfBytes,
			      Overlapped->offset) ;

	}
      else if (Overlapped->opcode == BLUE_FSDARWIN_WRITE)
	{
	  Overlapped->dwResult = 
	    (BLUE_INT) pwrite (Overlapped->fd,
			       (void *) Overlapped->lpBuffer,
			       Overlapped->nNumberOfBytes,
			       Overlapped->offset) ;
	}
      if (Overlapped->opcode != BLUE_FSDARWIN_NOOP)
	{
	  if (Overlapped->dwResult < 0)
	    Overlapped->Errno = errno ;
	  BlueEventSet (Overlapped->hEvent) ;
	}
    }
  return (0) ;
}

BLUE_VOID BlueFSDarwinStartup (BLUE_VOID)
{
  BlueFSRegister (BLUE_FS_DARWIN, &BlueFSDarwinInfo) ;

  BlueFSDarwinAIOFreeQ = BlueQcreate() ;
  g_instance = 0 ;
}

BLUE_VOID BlueFSDarwinShutdown (BLUE_VOID)
{
  BLUE_HANDLE hOverlapped ;
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;

  for (hOverlapped = (BLUE_HANDLE) BlueQdequeue (BlueFSDarwinAIOFreeQ) ;
       hOverlapped != BLUE_HANDLE_NULL ;
       hOverlapped = (BLUE_HANDLE) BlueQdequeue (BlueFSDarwinAIOFreeQ))
    {
      Overlapped = BlueHandleLock (hOverlapped) ;
      if (Overlapped != BLUE_NULL)
	{
	  BlueThreadDelete (Overlapped->hThread);
	  Overlapped->opcode = BLUE_FSDARWIN_NOOP ;
	  BlueEventSet (Overlapped->hBusy) ;
	  BlueThreadWait (Overlapped->hThread);
	  
	  BlueEventDestroy(Overlapped->hEvent);
	  BlueEventDestroy(Overlapped->hBusy);
	  BlueHeapFree(Overlapped);
	  BlueHandleDestroy(hOverlapped);
	  BlueHandleUnlock(hOverlapped);
	}
    }
  BlueQdestroy(BlueFSDarwinAIOFreeQ);
  BlueFSDarwinAIOFreeQ = BLUE_HANDLE_NULL;
}

int BlueFSDarwinGetFD (BLUE_HANDLE hFile) 
{
  int fd ;
  BLUE_FS_DARWIN_CONTEXT *context ;

  fd = -1 ;
  context = BlueHandleLock (hFile) ;

  if (context == BLUE_NULL || context->backup)
    {
      BlueThreadSetVariable (BlueLastError, 
			     (BLUE_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      fd = context->fd ;
    }

  if (context != BLUE_NULL)
    BlueHandleUnlock (hFile) ;

  return (fd) ;
}

/** \} */
