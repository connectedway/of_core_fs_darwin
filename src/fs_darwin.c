/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
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
 * \defgroup OfcFSDarwin Darwin File Interface
 *
 * \ingroup OfcFS
 */

/** \{ */
typedef struct 
{
  int fd ;
  OFC_BOOL deleteOnClose ;
  OFC_CHAR *name ;
  OFC_CHAR *pattern ;
  DIR *dir ;
  struct dirent nextDirent ;
  int nextRet ;
  OFC_BOOL backup ;
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
  OFC_HANDLE hEvent ;
  OFC_HANDLE hBusy ;
  OFC_INT dwResult ;
  OFC_INT Errno ;
  OFC_OFFT offset ;
  OFC_HANDLE hThread ;
  OFC_LPCVOID lpBuffer ;
  OFC_DWORD nNumberOfBytes ;
  OFC_INT fd ;
} BLUE_FSDARWIN_OVERLAPPED ;

OFC_HANDLE OfcFSDarwinAIOFreeQ ;
static OFC_INT g_instance ;


/*
 * Error codes
 */
typedef struct
{
  OFC_UINT32 file_errno ;
  OFC_UINT32 blue_error ;
} ERRNO2FILE ;

#define ERRNO2FILE_MAX 34
static ERRNO2FILE errno2file[ERRNO2FILE_MAX] =
  {
    {EPERM, OFC_ERROR_ACCESS_DENIED},
    {ENOENT, OFC_ERROR_FILE_NOT_FOUND},
    {ESRCH, OFC_ERROR_INVALID_HANDLE},
    {EINTR, OFC_ERROR_GEN_FAILURE},
    {EIO, OFC_ERROR_IO_DEVICE},
    {ENXIO, OFC_ERROR_BAD_DEVICE},
    {EBADF, OFC_ERROR_INVALID_HANDLE},
    {EDEADLK, OFC_ERROR_LOCK_VIOLATION},
    {EACCES, OFC_ERROR_INVALID_ACCESS},
    {EFAULT, OFC_ERROR_INVALID_PARAMETER},
    {EBUSY, OFC_ERROR_BUSY},
    {EEXIST, OFC_ERROR_FILE_EXISTS},
    {EXDEV, OFC_ERROR_NOT_SAME_DEVICE},
    {ENOTDIR, OFC_ERROR_INVALID_ACCESS},
    {EISDIR, OFC_ERROR_DIRECTORY},
    {EINVAL, OFC_ERROR_BAD_ARGUMENTS},
    {ENFILE, OFC_ERROR_TOO_MANY_OPEN_FILES},
    {EMFILE, OFC_ERROR_TOO_MANY_OPEN_FILES},
    {ETXTBSY, OFC_ERROR_BUSY},
    {EFBIG, OFC_ERROR_FILE_INVALID},
    {ENOSPC, OFC_ERROR_DISK_FULL},
    {ESPIPE, OFC_ERROR_SEEK_ON_DEVICE},
    {EROFS, OFC_ERROR_WRITE_PROTECT},
    {EPIPE, OFC_ERROR_BROKEN_PIPE},
    {EAGAIN, OFC_ERROR_IO_INCOMPLETE},
    {EINPROGRESS, OFC_ERROR_IO_PENDING},
    {EOPNOTSUPP, OFC_ERROR_NOT_SUPPORTED},
    {ELOOP, OFC_ERROR_BAD_PATHNAME},
    {ENAMETOOLONG, OFC_ERROR_BAD_PATHNAME},
    {ENOTEMPTY, OFC_ERROR_DIR_NOT_EMPTY},
    {EDQUOT, OFC_ERROR_HANDLE_DISK_FULL},
    {ENOSYS, OFC_ERROR_NOT_SUPPORTED},
    {EOVERFLOW, OFC_ERROR_BUFFER_OVERFLOW},
    {ECANCELED, OFC_ERROR_OPERATION_ABORTED}
  } ;

static OFC_DWORD 
OfcFSDarwinAIOThread (OFC_HANDLE hThread, OFC_VOID *context) ;

static OFC_UINT32 TranslateError (OFC_UINT32 file_errno)
{
  OFC_INT low ;
  OFC_INT high ;
  OFC_INT cursor ;
  OFC_UINT32 blue_error ;

  blue_error = OFC_ERROR_GEN_FAILURE ;
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

static int Win32DesiredAccessToDarwinFlags (OFC_DWORD dwDesiredAccess)
{
  static OFC_DWORD dwWriteAccess =
    OFC_FILE_ADD_FILE | OFC_FILE_ADD_SUBDIRECTORY |
    OFC_FILE_APPEND_DATA |
    OFC_FILE_DELETE_CHILD |
    OFC_FILE_WRITE_ATTRIBUTES | OFC_FILE_WRITE_DATA |
    OFC_FILE_WRITE_EA |
    OFC_GENERIC_WRITE ;
  static OFC_DWORD dwReadAccess =
    OFC_FILE_LIST_DIRECTORY |
    OFC_FILE_READ_ATTRIBUTES | OFC_FILE_READ_DATA |
    OFC_FILE_READ_EA | OFC_FILE_TRAVERSE |
    OFC_GENERIC_READ ;
  static OFC_DWORD dwExecuteAccess =
    OFC_FILE_EXECUTE |
    OFC_GENERIC_EXECUTE ;

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
Win32CreationDispositionToDarwinFlags (OFC_DWORD dwCreationDisposition)
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
  if (dwCreationDisposition >= OFC_CREATE_NEW && 
      dwCreationDisposition <= OFC_TRUNCATE_EXISTING)
    oflag = map[dwCreationDisposition] ;
  return (oflag) ;
}

static int Win32FlagsAndAttrsToDarwinFlags (OFC_DWORD dwFlagsAndAttributes)
{
  int oflag ;

  oflag = 0 ;
  return (oflag) ;
}

static OFC_VOID Win32OpenModesToDarwinModes (OFC_DWORD dwDesiredAccess, 
					     OFC_DWORD dwShareMode,
					     OFC_DWORD dwCreationDisposition, 
					     OFC_DWORD dwFlagsAndAttributes,
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
  if (dwDesiredAccess & OFC_FILE_APPEND_DATA &&
      (!(dwDesiredAccess & OFC_FILE_WRITE_DATA)))
    *oflag |= O_APPEND ;
}

static OFC_LPSTR FilePath2DarwinPath (OFC_LPCTSTR lpFileName)
{
  OFC_LPCTSTR p ;
  OFC_LPSTR lpAsciiName ;

  p = lpFileName ;
  if (BlueCtstrncmp (lpFileName, TSTR("file:"), 5) == 0)
    p = lpFileName + 5 ;
  lpAsciiName = BlueCtstr2cstr (p) ;

  return (lpAsciiName) ;
}

static OFC_HANDLE OfcFSDarwinCreateFile (OFC_LPCTSTR lpFileName,
                                         OFC_DWORD dwDesiredAccess,
                                         OFC_DWORD dwShareMode,
                                         OFC_LPSECURITY_ATTRIBUTES
					  lpSecAttributes,
                                         OFC_DWORD dwCreationDisposition,
                                         OFC_DWORD dwFlagsAndAttributes,
                                         OFC_HANDLE hTemplateFile)
{
  OFC_HANDLE ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  int oflag ;
  mode_t mode ;
  OFC_CHAR *lpAsciiName ;

  context = BlueHeapMalloc (sizeof (BLUE_FS_DARWIN_CONTEXT)) ;
  context->fd = -1 ;
  context->deleteOnClose = OFC_FALSE ;
  context->backup = OFC_FALSE ;

  Win32OpenModesToDarwinModes (dwDesiredAccess, dwShareMode,
			      dwCreationDisposition, dwFlagsAndAttributes,
			      &oflag, &mode) ;
  
  if (dwFlagsAndAttributes & OFC_FILE_FLAG_DELETE_ON_CLOSE)
    context->deleteOnClose = OFC_TRUE ;

  /*
   * Strip and convert to non-unicode
   */
  lpAsciiName = FilePath2DarwinPath (lpFileName) ;

  context->name = BlueCstrdup (lpAsciiName) ;

  if (!(dwFlagsAndAttributes & OFC_FILE_FLAG_BACKUP_SEMANTICS))
    {
      context->fd = open (lpAsciiName, oflag, mode) ;
      if (context->fd < 0)
	{
	  BlueThreadSetVariable (OfcLastError, 
				 (OFC_DWORD_PTR) TranslateError(errno)) ;
	  BlueHeapFree (context->name) ;
	  BlueHeapFree (context) ;
	  ret = OFC_INVALID_HANDLE_VALUE ;
	}
      else
	ret = ofc_handle_create (OFC_HANDLE_FSDARWIN_FILE, context) ;
    }
  else
    {
      ret = ofc_handle_create (OFC_HANDLE_FSDARWIN_FILE, context) ;
      context->backup = OFC_TRUE ;
    }

  BlueHeapFree (lpAsciiName) ;

  return (ret) ;
}

static OFC_BOOL 
OfcFSDarwinCreateDirectory (OFC_LPCTSTR lpPathName,
			    OFC_LPSECURITY_ATTRIBUTES lpSecurityAttr) 
{
  OFC_BOOL ret ;
  int status ;
  mode_t mode ;
  OFC_CHAR *lpAsciiName ;

  lpAsciiName = FilePath2DarwinPath (lpPathName) ;
  mode = S_IRWXU | S_IRWXG | S_IRWXO ;

  status = mkdir (lpAsciiName, mode) ;

  BlueHeapFree (lpAsciiName) ;
  if (status < 0)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(errno)) ;
      ret = OFC_FALSE ;
    }
  else
    ret = OFC_TRUE ;

  return (ret) ;
}

static OFC_BOOL OfcFSDarwinWriteFile (OFC_HANDLE hFile,
                                      OFC_LPCVOID lpBuffer,
                                      OFC_DWORD nNumberOfBytesToWrite,
                                      OFC_LPDWORD lpNumberOfBytesWritten,
                                      OFC_HANDLE hOverlapped)
{
  OFC_BOOL ret ;
  ssize_t status ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;

  ret = OFC_FALSE ;
  context = ofc_handle_lock (hFile) ;

  if (context == OFC_NULL || context->backup)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      Overlapped = OFC_NULL ;
      if (hOverlapped != OFC_HANDLE_NULL)
	{
	  Overlapped = ofc_handle_lock (hOverlapped) ;
	}

      if (Overlapped != OFC_NULL)
	{
	  ofc_event_reset (Overlapped->hEvent) ;
	  Overlapped->fd = context->fd ;
	  Overlapped->lpBuffer = lpBuffer ;
	  Overlapped->nNumberOfBytes = nNumberOfBytesToWrite ;
	  Overlapped->opcode = BLUE_FSDARWIN_WRITE ;

	  BlueCTrace ("aio_write 0x%08x\n", 
		      (OFC_INT) Overlapped->offset) ;

	  ofc_event_set (Overlapped->hBusy) ;

	  BlueThreadSetVariable (OfcLastError, (OFC_DWORD_PTR) 
				 TranslateError(EINPROGRESS)) ;

	  ofc_handle_unlock (hOverlapped) ;
	  ret = OFC_FALSE ;
	}
      else
	{
	  status = write (context->fd, lpBuffer, nNumberOfBytesToWrite) ;

	  if (status >= 0)
	    {
	      if (lpNumberOfBytesWritten != OFC_NULL)
		*lpNumberOfBytesWritten = (OFC_DWORD) status ;
	      ret = OFC_TRUE ;
	    }
	  else
	    {
	      BlueThreadSetVariable (OfcLastError, 
				     (OFC_DWORD_PTR) TranslateError(errno)) ;
	      ret = OFC_FALSE ;
	    }
	}
    }

  if (context != OFC_NULL)
    ofc_handle_unlock (hFile) ;

  return (ret) ;
}

static OFC_BOOL OfcFSDarwinReadFile (OFC_HANDLE hFile,
                                     OFC_LPVOID lpBuffer,
                                     OFC_DWORD nNumberOfBytesToRead,
                                     OFC_LPDWORD lpNumberOfBytesRead,
                                     OFC_HANDLE hOverlapped)
{
  OFC_BOOL ret ;
  ssize_t status ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;

  ret = OFC_FALSE ;
  context = ofc_handle_lock (hFile) ;

  if (context == OFC_NULL || context->backup)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      Overlapped = OFC_NULL ;
      if (hOverlapped != OFC_HANDLE_NULL)
	Overlapped = ofc_handle_lock (hOverlapped) ;

      if (Overlapped != OFC_NULL)
	{
	  /*
	   * Offset should already be set
	   */
	  ofc_event_reset (Overlapped->hEvent) ;
	  Overlapped->fd = context->fd ;
	  Overlapped->lpBuffer = lpBuffer ;
	  Overlapped->nNumberOfBytes = nNumberOfBytesToRead ;
	  Overlapped->opcode = BLUE_FSDARWIN_READ ;

	  BlueCTrace ("aio_read 0x%08x\n", 
		      (OFC_INT) Overlapped->offset) ;

	  ofc_event_set (Overlapped->hBusy) ;

	  BlueThreadSetVariable (OfcLastError, 
				 (OFC_DWORD_PTR) TranslateError(EINPROGRESS)) ;

	  ofc_handle_unlock (hOverlapped) ;
	  ret = OFC_FALSE ;
	}
      else
	{
	  status = read (context->fd, lpBuffer, nNumberOfBytesToRead) ;

	  if (status > 0)
	    {
	      if (lpNumberOfBytesRead != OFC_NULL)
		*lpNumberOfBytesRead = (OFC_DWORD) status ;
	      ret = OFC_TRUE ;
	    }
	  else
	    {
	      ret = OFC_FALSE ;
	      if(status == 0)
		BlueThreadSetVariable (OfcLastError, (OFC_DWORD_PTR) 
				       OFC_ERROR_HANDLE_EOF) ;
	      else
		BlueThreadSetVariable (OfcLastError, (OFC_DWORD_PTR) 
				       TranslateError(errno)) ;
	    }
	}
    }

  if (context != OFC_NULL)
    ofc_handle_unlock (hFile) ;

  return (ret) ;
}

static OFC_BOOL OfcFSDarwinCloseHandle (OFC_HANDLE hFile)
{
  OFC_BOOL ret ;
  int status ;
  BLUE_FS_DARWIN_CONTEXT *context ;

  ret = OFC_FALSE ;
  context = ofc_handle_lock (hFile) ;

  if (context == OFC_NULL)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
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

	  ofc_handle_destroy (hFile) ;
	  BlueHeapFree (context->name) ;
	  BlueHeapFree (context) ;
	  ret = OFC_TRUE ;
	}
      else
	{
	  ret = OFC_FALSE ;
	  BlueThreadSetVariable (OfcLastError, 
				 (OFC_DWORD_PTR) TranslateError(errno)) ;
	}
      ofc_handle_unlock (hFile) ;
    }

  return (ret) ;

}

static OFC_BOOL OfcFSDarwinDeleteFile (OFC_LPCTSTR lpFileName) 
{
  OFC_BOOL ret ;
  int status ;
  OFC_CHAR *asciiName ;
  

  ret = OFC_TRUE ;
  asciiName = FilePath2DarwinPath (lpFileName) ;

  status = unlink (asciiName) ;
  BlueHeapFree (asciiName) ;

  if (status < 0)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(errno)) ;
      ret = OFC_FALSE ;
    }

  return (ret) ;
}

static OFC_BOOL OfcFSDarwinRemoveDirectory (OFC_LPCTSTR lpPathName) 
{
  OFC_BOOL ret ;
  int status ;
  OFC_CHAR *asciiName ;

  ret = OFC_TRUE ;
  asciiName = FilePath2DarwinPath (lpPathName) ;
  status = rmdir (asciiName) ;

  BlueHeapFree (asciiName) ;
  if (status < 0)
    {
      ret = OFC_FALSE ;
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}

static OFC_BOOL GetWin32FindFileData (OFC_CHAR *asciiName, 
				       OFC_CCHAR *dName,
				       OFC_LPWIN32_FIND_DATAW lpFindFileData)

{
  struct stat sb ;
  int status ;
  OFC_BOOL ret ;
  OFC_TCHAR *tcharName ;

  ret = OFC_FALSE ;
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
	lpFindFileData->dwFileAttributes |= OFC_FILE_ATTRIBUTE_READONLY ;
      if (sb.st_mode & S_IFDIR)
	lpFindFileData->dwFileAttributes |= OFC_FILE_ATTRIBUTE_DIRECTORY ;
      if (lpFindFileData->dwFileAttributes == 0)
	lpFindFileData->dwFileAttributes |= OFC_FILE_ATTRIBUTE_NORMAL ;
      if (dName[0] == '.')
	lpFindFileData->dwFileAttributes |= OFC_FILE_ATTRIBUTE_HIDDEN ;
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
      BlueCtstrncpy (lpFindFileData->cFileName, tcharName, OFC_MAX_PATH) ;
      BlueHeapFree (tcharName) ;

      lpFindFileData->cAlternateFileName[0] = TCHAR_EOS ;
      ret = OFC_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}
      
static OFC_BOOL 
GetWin32FileAttributeData (OFC_CHAR *asciiName, 
			   OFC_WIN32_FILE_ATTRIBUTE_DATA *fadata) 
{
  OFC_BOOL ret ;
  struct stat sb ;
  int status ;

  ret = OFC_FALSE ;

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
	fadata->dwFileAttributes |= OFC_FILE_ATTRIBUTE_READONLY ;
      if (sb.st_mode & S_IFDIR)
	{
	  fadata->dwFileAttributes |= OFC_FILE_ATTRIBUTE_DIRECTORY ;
	}
      if (fadata->dwFileAttributes == 0)
	fadata->dwFileAttributes |= OFC_FILE_ATTRIBUTE_NORMAL ;
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

      ret = OFC_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(errno)) ;
    }
  return (ret) ;
}

static OFC_BOOL GetWin32FileBasicInfo (int fd, 
					OFC_CHAR *name,
					OFC_FILE_BASIC_INFO *lpFileInformation)
{
  OFC_BOOL ret ;
  OFC_FILETIME filetime;
  struct stat sb ;
  int status ;

  ret = OFC_FALSE ;

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
#if defined(OFC_64BIT_INTEGER)
      lpFileInformation->CreationTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(OFC_LARGE_INTEGER) filetime.dwLowDateTime ;
      lpFileInformation->LastWriteTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(OFC_LARGE_INTEGER) filetime.dwLowDateTime ;
#else
      lpFileInformation->CreationTime.high = filetime.dwHighDateTime ;
      lpFileInformation->CreationTime.low = filetime.dwLowDateTime ;
      lpFileInformation->LastWriteTime.high = filetime.dwHighDateTime ;
      lpFileInformation->LastWriteTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_atimespec.tv_sec,
			   sb.st_atimespec.tv_nsec, &filetime) ;
#if defined(OFC_64BIT_INTEGER)
      lpFileInformation->LastAccessTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(OFC_LARGE_INTEGER) filetime.dwLowDateTime ;
#else
      lpFileInformation->LastAccessTime.high = filetime.dwHighDateTime ;
      lpFileInformation->LastAccessTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_ctimespec.tv_sec,
			   sb.st_ctimespec.tv_nsec, &filetime) ;
#if defined(OFC_64BIT_INTEGER)
      lpFileInformation->ChangeTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
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
	lpFileInformation->FileAttributes |= OFC_FILE_ATTRIBUTE_READONLY ;
      if (sb.st_mode & S_IFDIR)
	lpFileInformation->FileAttributes |= OFC_FILE_ATTRIBUTE_DIRECTORY ;
      if (lpFileInformation->FileAttributes == 0)
	lpFileInformation->FileAttributes |= OFC_FILE_ATTRIBUTE_NORMAL ;
      ret = OFC_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}

static OFC_BOOL GetWin32FileInternalInfo (int fd, 
					   OFC_CHAR *name,
					   OFC_FILE_INTERNAL_INFO *lpFileInformation)
{
  OFC_BOOL ret ;

  ret = OFC_TRUE ;

  lpFileInformation->IndexNumber = 0L ;


  return (ret) ;
}

static OFC_BOOL GetWin32FileNetworkOpenInfo (int fd, 
					      OFC_CHAR *name,
					      OFC_FILE_NETWORK_OPEN_INFO *lpFileInformation)
{
  OFC_BOOL ret ;
  OFC_FILETIME filetime;
  struct stat sb ;
  int status ;

  ret = OFC_FALSE ;

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
#if defined(OFC_64BIT_INTEGER)
      lpFileInformation->CreationTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(OFC_LARGE_INTEGER) filetime.dwLowDateTime ;
      lpFileInformation->LastWriteTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(OFC_LARGE_INTEGER) filetime.dwLowDateTime ;
#else
      lpFileInformation->CreationTime.high = filetime.dwHighDateTime ;
      lpFileInformation->CreationTime.low = filetime.dwLowDateTime ;
      lpFileInformation->LastWriteTime.high = filetime.dwHighDateTime ;
      lpFileInformation->LastWriteTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_atimespec.tv_sec,
			   sb.st_atimespec.tv_nsec, &filetime) ;
#if defined(OFC_64BIT_INTEGER)
      lpFileInformation->LastAccessTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	(OFC_LARGE_INTEGER) filetime.dwLowDateTime ;
#else
      lpFileInformation->LastAccessTime.high = filetime.dwHighDateTime ;
      lpFileInformation->LastAccessTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_ctimespec.tv_sec,
			   sb.st_ctimespec.tv_nsec, &filetime) ;
#if defined(OFC_64BIT_INTEGER)
      lpFileInformation->ChangeTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
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
	lpFileInformation->FileAttributes |= OFC_FILE_ATTRIBUTE_READONLY ;
      if (sb.st_mode & S_IFDIR)
	lpFileInformation->FileAttributes |= OFC_FILE_ATTRIBUTE_DIRECTORY ;
      if (lpFileInformation->FileAttributes == 0)
	lpFileInformation->FileAttributes |= OFC_FILE_ATTRIBUTE_NORMAL ;
#if defined(OFC_64BIT_INTEGER)
      lpFileInformation->AllocationSize = 
	sb.st_blocks * OFC_FS_DARWIN_BLOCK_SIZE ;
      lpFileInformation->EndOfFile = sb.st_size ;
#else
      lpFileInformation->AllocationSize.low = 
	sb.st_blocks * OFC_FS_DARWIN_BLOCK_SIZE ;
      lpFileInformation->EndOfFile.low = sb.st_size ;
      lpFileInformation->AllocationSize.high = 0 ;
      lpFileInformation->EndOfFile.high = 0 ;
#endif      
      ret = OFC_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}

static OFC_BOOL 
GetWin32FileStandardInfo (int fd, 
			  OFC_CHAR *name,
			  OFC_FILE_STANDARD_INFO *lpFileInformation,
			  OFC_BOOL delete_pending)
{
  OFC_BOOL ret ;
  struct stat sb ;
  int status ;

  ret = OFC_FALSE ;

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
#if defined(OFC_64BIT_INTEGER)
      lpFileInformation->AllocationSize = 
	sb.st_blocks * OFC_FS_DARWIN_BLOCK_SIZE ;
      lpFileInformation->EndOfFile = sb.st_size ;
#else
      lpFileInformation->AllocationSize.low = 
	sb.st_blocks * OFC_FS_DARWIN_BLOCK_SIZE ;
      lpFileInformation->EndOfFile.low = sb.st_size ;
      lpFileInformation->AllocationSize.high = 0 ;
      lpFileInformation->EndOfFile.high = 0 ;
#endif      
      lpFileInformation->NumberOfLinks = sb.st_nlink ;
      lpFileInformation->DeletePending = delete_pending ;
      lpFileInformation->Directory = OFC_FALSE ;
      if (sb.st_mode & S_IFDIR)
	lpFileInformation->Directory = OFC_TRUE ;
      ret = OFC_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}

static OFC_BOOL GetWin32FileNameInfo (int fd,
				       OFC_CHAR *name,
				       OFC_FILE_NAME_INFO *lpFileInformation,
				       OFC_DWORD dwBufferSize)
{
  OFC_TCHAR *tcharName ;

  tcharName = BlueCcstr2tstr (name) ;
  lpFileInformation->FileNameLength = (OFC_DWORD) BlueCtstrlen (tcharName) *
    sizeof (OFC_TCHAR) ;
  BlueCmemcpy (lpFileInformation->FileName, tcharName,
	       BLUE_C_MIN (dwBufferSize - sizeof (OFC_DWORD),
			   lpFileInformation->FileNameLength)) ;
  BlueHeapFree (tcharName) ;
  return (OFC_TRUE) ;
}


static OFC_BOOL 
GetWin32FileIdBothDirInfo (int fd,
			   OFC_CHAR *name,
			   OFC_FILE_ID_BOTH_DIR_INFO *lpFileInfo,
			   OFC_DWORD dwBufferSize)
{
  OFC_BOOL ret ;
  struct stat sb ;
  int status ;
  OFC_TCHAR *tcharName ;
  OFC_FILETIME filetime ;

  ret = OFC_FALSE ;

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
#if defined(OFC_64BIT_INTEGER)
      lpFileInfo->CreationTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	filetime.dwLowDateTime ;
      lpFileInfo->LastWriteTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	filetime.dwLowDateTime ;
#else
      lpFileInfo->CreationTime.high = filetime.dwHighDateTime ;
      lpFileInfo->CreationTime.low = filetime.dwLowDateTime ;
      lpFileInfo->LastWriteTime.high = filetime.dwHighDateTime ;
      lpFileInfo->LastWriteTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_atimespec.tv_sec,
			   sb.st_atimespec.tv_nsec, &filetime) ;
#if defined(OFC_64BIT_INTEGER)
      lpFileInfo->LastAccessTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	filetime.dwLowDateTime ;
#else
      lpFileInfo->LastAccessTime.high = filetime.dwHighDateTime ;
      lpFileInfo->LastAccessTime.low = filetime.dwLowDateTime ;
#endif
      EpochTimeToFileTime (sb.st_ctimespec.tv_sec,
			   sb.st_ctimespec.tv_nsec, &filetime) ;
#if defined(OFC_64BIT_INTEGER)
      lpFileInfo->ChangeTime = 
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) | 
	filetime.dwLowDateTime ;
      lpFileInfo->EndOfFile = sb.st_size ;
      lpFileInfo->AllocationSize = 
	sb.st_blocks * OFC_FS_DARWIN_BLOCK_SIZE ;
#else
      lpFileInfo->ChangeTime.high = filetime.dwHighDateTime ;
      lpFileInfo->ChangeTime.low = filetime.dwLowDateTime ;
      lpFileInfo->EndOfFile.low = sb.st_size ;
      lpFileInfo->EndOfFile.high = 0 ;
      lpFileInfo->AllocationSize.low = 
	sb.st_blocks * OFC_FS_DARWIN_BLOCK_SIZE ;
      lpFileInfo->AllocationSize.high = 0 ;
#endif
      lpFileInfo->FileAttributes = 0 ;
      /*
       * We do not support hidden files or System Files or Archive Files
       * or temporary or sparse or compressed,or offline, or encrypted,
       * or virtual
       */
      if (sb.st_flags & UF_IMMUTABLE)
	lpFileInfo->FileAttributes |= OFC_FILE_ATTRIBUTE_READONLY ;
      if (sb.st_mode & S_IFDIR)
	lpFileInfo->FileAttributes |= OFC_FILE_ATTRIBUTE_DIRECTORY ;
      if (lpFileInfo->FileAttributes == 0)
	lpFileInfo->FileAttributes |= OFC_FILE_ATTRIBUTE_NORMAL ;

      tcharName = BlueCcstr2tstr (name) ;
      lpFileInfo->FileNameLength = (OFC_DWORD) BlueCtstrlen (tcharName) *
	sizeof (OFC_TCHAR) ;
      lpFileInfo->EaSize = 0 ;
      lpFileInfo->ShortNameLength = 0 ;
      lpFileInfo->ShortName[0] = TCHAR_EOS ;
      lpFileInfo->FileId = 0 ;
      BlueCmemcpy (lpFileInfo->FileName, tcharName,
		   BLUE_C_MIN (dwBufferSize - 
			       sizeof (OFC_FILE_ID_BOTH_DIR_INFO) - 
			       sizeof (OFC_TCHAR),
			       lpFileInfo->FileNameLength)) ;
      BlueHeapFree (tcharName) ;
      ret = OFC_TRUE ;
    }
  else
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(errno)) ;
    }

  return (ret) ;
}

static OFC_HANDLE
OfcFSDarwinFindFirstFile (OFC_LPCTSTR lpFileName,
			  OFC_LPWIN32_FIND_DATAW lpFindFileData,
			  OFC_BOOL *more) 
{
  OFC_HANDLE hRet ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  OFC_CHAR *asciiName ;
  OFC_TCHAR *tcharName ;
  struct dirent *dirent ;
  OFC_CHAR *pathname ;
  OFC_SIZET len ;
  BLUE_PATH *path ;
  OFC_LPTSTR cursor ;
  OFC_LPCTSTR filename ;

  context = BlueHeapMalloc (sizeof (BLUE_FS_DARWIN_CONTEXT)) ;

  hRet = OFC_INVALID_HANDLE_VALUE ;
  if (context != OFC_NULL)
    {
      context->pattern = OFC_NULL ;

      path = BluePathCreateW (lpFileName) ;
      filename = BluePathFilename (path) ;
      if (filename != OFC_NULL)
	{
	  context->pattern = BlueCtstr2cstr(filename) ;
	  BluePathFreeFilename (path) ;
	}

      BluePathSetType (path, OFC_FST_DARWIN) ;
      len = 0 ;
      len = BluePathPrintW (path, NULL, &len) + 1 ;
      tcharName = BlueHeapMalloc (len * sizeof (OFC_TCHAR)) ;
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
				 OFC_FILE_MATCH_PATHNAME |
				 OFC_FILE_MATCH_CASEFOLD) ;
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

	      *more = OFC_FALSE ;

	      for (context->nextRet = readdir_r (context->dir,
						 &context->nextDirent,
						 &dirent) ;
		   dirent != NULL && 
		     !BlueFileMatch (context->pattern, dirent->d_name,
				     OFC_FILE_MATCH_PATHNAME |
				     OFC_FILE_MATCH_CASEFOLD) ;
		   context->nextRet = readdir_r (context->dir,
						 &context->nextDirent,
						 &dirent) ) ;

	      if (dirent != NULL)
		*more = OFC_TRUE ;
	      else
		{
		  context->nextRet = 1 ;
		}
	    }
	}

      if (context->dir == NULL)
	{
	  BlueThreadSetVariable (OfcLastError, 
				 (OFC_DWORD_PTR) TranslateError(errno)) ;
	  BlueHeapFree (context->name) ;
	  if (context->pattern != NULL)
	    BlueHeapFree (context->pattern) ;
	  BlueHeapFree (context) ;
	}
      else
	hRet = ofc_handle_create (OFC_HANDLE_FSWIN32_FILE, context) ;
    }

  return (hRet) ;
}

static OFC_BOOL 
OfcFSDarwinFindNextFile (OFC_HANDLE hFindFile,
                         OFC_LPWIN32_FIND_DATAW lpFindFileData,
                         OFC_BOOL *more)
{
  struct dirent *dirent ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  OFC_BOOL ret ;
  OFC_CHAR *pathname ;
  OFC_SIZET len ;

  ret = OFC_FALSE ;
  *more = OFC_FALSE ;
  context = ofc_handle_lock (hFindFile) ;

  if (context == OFC_NULL)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      if (context->nextRet == 0)
	{
	  ret = OFC_TRUE ;
	  len = BlueCstrlen(context->name) + 
	    BlueCstrlen (context->nextDirent.d_name) ;
	  pathname = BlueHeapMalloc (len+2) ;
	  BlueCsnprintf (pathname, len+2, "%s/%s", 
			 context->name, 
			 context->nextDirent.d_name) ;
	  ret = GetWin32FindFileData (pathname, context->nextDirent.d_name,
				      lpFindFileData) ;
	  BlueHeapFree (pathname) ;

	  if (ret == OFC_TRUE)
	    {
	      for (context->nextRet = readdir_r (context->dir,
						 &context->nextDirent,
						 &dirent) ;
		   dirent != NULL && 
		     !BlueFileMatch (context->pattern, dirent->d_name,
				     OFC_FILE_MATCH_PATHNAME |
				     OFC_FILE_MATCH_CASEFOLD) ;
		   context->nextRet = readdir_r (context->dir,
						 &context->nextDirent,
						 &dirent) ) ;

	      if (dirent != NULL)
		*more = OFC_TRUE ;
	      else
		{
		  context->nextRet = 1 ;
		}
	    }
	}
      else if (context->nextRet == 1)
	BlueThreadSetVariable (OfcLastError, (OFC_DWORD_PTR)
			       OFC_ERROR_NO_MORE_FILES) ;
      else
	BlueThreadSetVariable (OfcLastError, 
			       (OFC_DWORD_PTR) TranslateError(errno)) ;

      ofc_handle_unlock (hFindFile) ;
    }

  return (ret) ;
}

static OFC_BOOL OfcFSDarwinFindClose (OFC_HANDLE hFindFile)
{
  OFC_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  int status ;

  ret = OFC_FALSE ;
  context = ofc_handle_lock (hFindFile) ;

  if (context == OFC_NULL)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      status = closedir (context->dir) ;
      if (status == 0)
	{
	  ret = OFC_TRUE ;
	  ofc_handle_destroy (hFindFile) ;
	  BlueHeapFree (context->name) ;
	  if (context->pattern != OFC_NULL)
	    BlueHeapFree (context->pattern) ;
	  BlueHeapFree (context) ;
	}
      else
	BlueThreadSetVariable (OfcLastError, 
			       (OFC_DWORD_PTR) TranslateError(errno)) ;

      ofc_handle_unlock (hFindFile) ;
    }

  return (ret) ;
}

static OFC_BOOL OfcFSDarwinFlushFileBuffers (OFC_HANDLE hFile)
{
  /*
   * No flush needed
   */
  return (OFC_TRUE) ;
}

static OFC_BOOL 
OfcFSDarwinGetFileAttributesEx (OFC_LPCTSTR lpFileName,
				OFC_GET_FILEEX_INFO_LEVELS fInfoLevelId,
				OFC_LPVOID lpFileInformation) 
{
  OFC_BOOL ret ;
  OFC_CHAR *asciiName ;

  ret = OFC_FALSE ;
  /*
   * This is the only one we support
   */
  if (fInfoLevelId == OfcGetFileExInfoStandard)
    {
      asciiName = FilePath2DarwinPath (lpFileName) ;
      ret = GetWin32FileAttributeData (asciiName, lpFileInformation) ;
      BlueHeapFree (asciiName) ;
    }
  return (ret) ;
}

static OFC_BOOL 
OfcFSDarwinGetFileInformationByHandleEx 
(OFC_HANDLE hFile,
 OFC_FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
 OFC_LPVOID lpFileInformation,
 OFC_DWORD dwBufferSize) 
{
  OFC_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;

  ret = OFC_FALSE ;

  context = ofc_handle_lock (hFile) ;
  if (context == OFC_NULL)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      switch (FileInformationClass)
	{
	case OfcFileNetworkOpenInfo:
	  if (dwBufferSize >= sizeof (OFC_FILE_NETWORK_OPEN_INFO))
	    {
	      ret = GetWin32FileNetworkOpenInfo (context->fd, 
						 context->name,
						 lpFileInformation) ;
	    }
	  break ;

	case OfcFileInternalInformation:
	  if (dwBufferSize >= sizeof (OFC_FILE_INTERNAL_INFO))
	    {
	      ret = GetWin32FileInternalInfo (context->fd,
					      context->name,
					      lpFileInformation) ;
	    }
	  break ;

	case OfcFileBasicInfo:
	  if (dwBufferSize >= sizeof (OFC_FILE_BASIC_INFO))
	    {
	      ret = GetWin32FileBasicInfo (context->fd, 
					   context->name,
					   lpFileInformation) ;
	    }
	  break ;

	case OfcFileStandardInfo:
	  if (dwBufferSize >= sizeof (OFC_FILE_STANDARD_INFO))
	    {
	      ret = GetWin32FileStandardInfo (context->fd, 
					      context->name,
					      lpFileInformation,
					      context->deleteOnClose) ;
	    }
	  break ;

	case OfcFileNameInfo:
	  if (dwBufferSize >= sizeof (OFC_FILE_NAME_INFO) - sizeof(BLUE_WCHAR))
	    {
	      ret = GetWin32FileNameInfo (context->fd, context->name,
					  lpFileInformation, 
					  dwBufferSize) ;
	    }
	  break ;

	case OfcFileEndOfFileInfo:
	case OfcFileRenameInfo:
	case OfcFileDispositionInfo:
	case OfcFileAllocationInfo:
	case OfcFileInfoStandard:
	  /*
	   * These are for sets. They don't apply for get
	   */
	  break ;

	default:
	case OfcFileStreamInfo:
	case OfcFileCompressionInfo:
	case OfcFileAttributeTagInfo:
	case OfcFileIdBothDirectoryRestartInfo:
	  /*
	   * These are not supported
	   */
	  break ;

	case OfcFileIdBothDirectoryInfo:
	  if (dwBufferSize >= sizeof (OFC_FILE_ID_BOTH_DIR_INFO) - 
	      sizeof (BLUE_WCHAR))
	    {
	      ret = GetWin32FileIdBothDirInfo (context->fd, context->name,
					       lpFileInformation, 
					       dwBufferSize) ;
	    }
	  break ;

	case OfcFileAllInfo:
	  if (dwBufferSize >= sizeof (OFC_FILE_ALL_INFO) - 
	      sizeof (BLUE_WCHAR))
	    {
	      OFC_FILE_ALL_INFO *lpAllInformation =
		(OFC_FILE_ALL_INFO *) lpFileInformation ;

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
		      OFC_FILE_ATTRIBUTE_DIRECTORY)
		    {
		      lpAllInformation->AccessInfo.AccessFlags =
			OFC_FILE_LIST_DIRECTORY |
			OFC_FILE_ADD_FILE |
			OFC_FILE_ADD_SUBDIRECTORY |
			OFC_FILE_DELETE_CHILD |
			OFC_FILE_READ_ATTRIBUTES |
			OFC_FILE_WRITE_ATTRIBUTES |
			OFC_DELETE ;
		    }
		  else
		    {
		      lpAllInformation->AccessInfo.AccessFlags =
			OFC_FILE_READ_DATA |
			OFC_FILE_WRITE_DATA |
			OFC_FILE_APPEND_DATA |
			OFC_FILE_EXECUTE |
			OFC_FILE_READ_ATTRIBUTES |
			OFC_FILE_WRITE_ATTRIBUTES |
			OFC_DELETE ;
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
					      sizeof (OFC_FILE_ALL_INFO)) ;
		}
	    }
	  break ;
	}
      ofc_handle_unlock (hFile) ;
    }

  return (ret) ;
}

static OFC_BOOL OfcFSDarwinMoveFile (OFC_LPCTSTR lpExistingFileName,
				      OFC_LPCTSTR lpNewFileName) 
{
  OFC_BOOL ret ;
  int status ;

  OFC_CHAR *asciiExisting ;
  OFC_CHAR *asciiNew ;

  ret = OFC_TRUE ;
  asciiExisting = FilePath2DarwinPath (lpExistingFileName) ;
  asciiNew = FilePath2DarwinPath (lpNewFileName) ;

  status = rename (asciiExisting, asciiNew) ;
  BlueHeapFree (asciiExisting);
  BlueHeapFree (asciiNew) ;

  if (status < 0)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(errno)) ;
      ret = OFC_FALSE ;
    }

  return (ret) ;
}

OFC_HANDLE OfcFSDarwinGetOverlappedEvent (OFC_HANDLE hOverlapped)
{
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;
  OFC_HANDLE hRet ;

  hRet = OFC_HANDLE_NULL ;
  Overlapped = ofc_handle_lock (hOverlapped) ;
  if (Overlapped != OFC_NULL)
    {
      hRet = Overlapped->hEvent ;
      ofc_handle_unlock (hOverlapped) ;
    }
  return (hRet) ;
}

static OFC_HANDLE OfcFSDarwinCreateOverlapped (OFC_VOID)
{
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;
  OFC_HANDLE hRet ;

  hRet = OFC_HANDLE_NULL ;

  hRet = (OFC_HANDLE) BlueQdequeue (OfcFSDarwinAIOFreeQ) ;
  if (hRet == OFC_HANDLE_NULL)
    {
      Overlapped = BlueHeapMalloc (sizeof (BLUE_FSDARWIN_OVERLAPPED)) ;
      if (Overlapped != OFC_NULL)
	{
	  hRet = ofc_handle_create (OFC_HANDLE_FSDARWIN_OVERLAPPED,
                                Overlapped) ;
	  Overlapped->offset = 0 ;
	  Overlapped->hEvent = ofc_event_create (OFC_EVENT_MANUAL) ;
	  Overlapped->hBusy = ofc_event_create (OFC_EVENT_AUTO) ;

	  Overlapped->hThread = BlueThreadCreate (&OfcFSDarwinAIOThread,
                                              BLUE_THREAD_AIO,
                                              g_instance++,
                                              Overlapped,
                                              BLUE_THREAD_JOIN,
                                              OFC_HANDLE_NULL) ;
	}
    }

  if (hRet != OFC_HANDLE_NULL)
    {
      Overlapped = ofc_handle_lock (hRet) ;
      if (Overlapped != OFC_NULL)
	{
	  Overlapped->Errno = 0 ;
	  ofc_handle_unlock (hRet) ;
	}
    }
  return (hRet) ;
}

OFC_VOID OfcFSDarwinDestroyOverlapped (OFC_HANDLE hOverlapped)
{
  BlueQenqueue (OfcFSDarwinAIOFreeQ, (OFC_VOID *) hOverlapped) ;
}

OFC_VOID OfcFSDarwinSetOverlappedOffset (OFC_HANDLE hOverlapped,
                                         OFC_OFFT offset)
{
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;

  Overlapped = ofc_handle_lock (hOverlapped) ;
  if (Overlapped != OFC_NULL)
    {
      Overlapped->offset = offset ;
      ofc_handle_unlock (hOverlapped) ;
    }
}

static OFC_BOOL 
OfcFSDarwinGetOverlappedResult (OFC_HANDLE hFile,
                                OFC_HANDLE hOverlapped,
                                OFC_LPDWORD lpNumberOfBytesTransferred,
                                OFC_BOOL bWait)
{
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  OFC_BOOL ret ;

  ret = OFC_FALSE ;
  context = ofc_handle_lock (hFile) ;

  if (context == OFC_NULL || context->backup)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      Overlapped = ofc_handle_lock (hOverlapped) ;
      if (Overlapped != OFC_NULL)
	{
	  if (bWait)
	    ofc_event_wait (Overlapped->hEvent) ;

	  if (ofc_event_test (Overlapped->hEvent))
	    {
	      if (Overlapped->dwResult < 0)
		{
		  BlueThreadSetVariable (OfcLastError, 
					 (OFC_DWORD_PTR) 
					 TranslateError(Overlapped->Errno)) ;
		}
	      else
		{
		  *lpNumberOfBytesTransferred = Overlapped->dwResult ;
		  ret = OFC_TRUE ;
		}
	    }
	  else
	    {
	      BlueThreadSetVariable (OfcLastError, 
				     (OFC_DWORD_PTR) 
				     TranslateError(EINPROGRESS)) ;
	    }
	  ofc_handle_unlock (hOverlapped) ;
	}
    }

  if (context != OFC_NULL)
    ofc_handle_unlock (hFile) ;

  return (ret) ;
}

static OFC_BOOL OfcFSDarwinSetEndOfFile (OFC_HANDLE hFile)
{
  OFC_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  off_t offset ;
  int status ;

  ret = OFC_FALSE ;
  context = ofc_handle_lock (hFile) ;

  if (context == OFC_NULL || context->backup)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
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
	    ret = OFC_TRUE ;
	  else
	    BlueThreadSetVariable (OfcLastError, 
				   (OFC_DWORD_PTR) TranslateError(errno)) ;
	}
      else
	BlueThreadSetVariable (OfcLastError, 
			       (OFC_DWORD_PTR) TranslateError(errno)) ;
    }

  if (context != OFC_NULL)
    ofc_handle_unlock (hFile) ;

  return (ret) ;
}

static OFC_BOOL OfcFSDarwinSetFileAttributes (OFC_LPCTSTR lpFileName,
					       OFC_DWORD dwFileAttributes)
{
  OFC_BOOL ret ;

  /*
   * We can't set file attributes on Darwin
   */
  ret = OFC_TRUE ;

  return (ret) ;
}

static OFC_BOOL 
OfcFSDarwinSetFileInformationByHandle (OFC_HANDLE hFile,
                                       OFC_FILE_INFO_BY_HANDLE_CLASS
				       FileInformationClass,
                                       OFC_LPVOID lpFileInformation,
                                       OFC_DWORD dwBufferSize)
{
  OFC_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;

  ret = OFC_FALSE ;
  context = ofc_handle_lock (hFile) ;

  if (context == OFC_NULL)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      switch (FileInformationClass)
	{
	case OfcFileBasicInfo:
	  ret = OFC_TRUE;
	  break ;
	  
	default:
	  break ;

	case OfcFileAllocationInfo:
	  {
	    OFC_FILE_ALLOCATION_INFO *info ;
	    off_t offset ;

	    if (lpFileInformation != OFC_NULL)
	      {
		info = lpFileInformation ;

		offset = (off_t) info->AllocationSize ;
		if (ftruncate (context->fd, offset) == 0)
		  ret = OFC_TRUE ;
		else
		  BlueThreadSetVariable (OfcLastError, 
					 (OFC_DWORD_PTR) 
					 TranslateError(errno)) ;
	      }
	  }
	  break ;

	case OfcFileRenameInfo:
	  {
	    OFC_FILE_RENAME_INFO *rename_info ;
	    OFC_TCHAR *to_name ;
	    OFC_CHAR *sztoname ;
	    int status ;
	    OFC_CHAR *p ;

	    if (lpFileInformation != OFC_NULL)
	      {
		rename_info = lpFileInformation ;

		/* get the to name */
		to_name = BlueHeapMalloc (rename_info->FileNameLength +
					  sizeof (OFC_TCHAR)) ;
		BlueCtstrncpy (to_name, rename_info->FileName,
			       (rename_info->FileNameLength /
				sizeof(OFC_TCHAR))) ;
		to_name[rename_info->FileNameLength / sizeof (OFC_TCHAR)] =
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
		  ret = OFC_TRUE ;
		else
		  BlueThreadSetVariable 
		    (OfcLastError, 
		     (OFC_DWORD_PTR) TranslateError(errno)) ;
	      }
	  }
	  break ;

	case OfcFileEndOfFileInfo:
	  {
	    OFC_FILE_END_OF_FILE_INFO *fileEof ;
	    off_t offset ;
	    int status ;

	    if (lpFileInformation != OFC_NULL)
	      {
		fileEof = lpFileInformation ;
		offset = (off_t) fileEof->EndOfFile ;
		offset = lseek (context->fd, offset, SEEK_SET) ;
		if (offset >= 0)
		  {
		    status = ftruncate (context->fd, offset) ;
		    if (status == 0)
		      ret = OFC_TRUE ;
		    else
		      BlueThreadSetVariable (OfcLastError, 
					     (OFC_DWORD_PTR) 
					     TranslateError(errno)) ;
		  }
		else
		  BlueThreadSetVariable (OfcLastError, 
					 (OFC_DWORD_PTR) TranslateError(errno)) ;
	      }
	  }
	  break ;

	case OfcFileDispositionInfo:
	  {
	    OFC_FILE_DISPOSITION_INFO *fileDisposition ;

	    if (lpFileInformation != OFC_NULL)
	      {
		fileDisposition = lpFileInformation ;

		context->deleteOnClose = fileDisposition->DeleteFile ;
		ret = OFC_TRUE ;
	      }
	  }
	  break ;
	}
    }

  if (context != OFC_NULL)
    ofc_handle_unlock (hFile) ;

  return ((OFC_BOOL) ret) ;
}

static OFC_DWORD OfcFSDarwinSetFilePointer (OFC_HANDLE hFile,
                                            OFC_LONG lDistanceToMove,
                                            OFC_PLONG lpDistanceToMoveHigh,
                                            OFC_DWORD dwMoveMethod)
{
  OFC_DWORD ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  off_t offset ;
  int whence ;

  ret = OFC_INVALID_SET_FILE_POINTER ;
  context = ofc_handle_lock (hFile) ;

  if (context == OFC_NULL || context->backup)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      switch (dwMoveMethod)
	{
	default:
	case OFC_FILE_BEGIN:
	  whence = SEEK_SET ;
	  break ;
	case OFC_FILE_END:
	  whence = SEEK_END ;
	  break ;
	case OFC_FILE_CURRENT:
	  whence = SEEK_CUR ;
	  break ;
	}

      offset = lDistanceToMove ;
      if (sizeof (off_t) > sizeof (OFC_LONG) && 
	  lpDistanceToMoveHigh != OFC_NULL)
	offset |= (off_t) *lpDistanceToMoveHigh << 32 ;

      offset = lseek (context->fd, offset, whence) ;
      if (offset >= 0)
	ret = (OFC_DWORD) (offset & 0xFFFFFFFF) ;
      else
	BlueThreadSetVariable (OfcLastError, 
			       (OFC_DWORD_PTR) TranslateError(errno)) ;

    }

  if (context != OFC_NULL)
    ofc_handle_unlock (hFile) ;

  return (ret) ;
}

static OFC_BOOL 
OfcFSDarwinTransactNamedPipe (OFC_HANDLE hFile,
                              OFC_LPVOID lpInBuffer,
                              OFC_DWORD nInBufferSize,
                              OFC_LPVOID lpOutBuffer,
                              OFC_DWORD nOutBufferSize,
                              OFC_LPDWORD lpBytesRead,
                              OFC_HANDLE hOverlapped)
{
  return (OFC_FALSE) ;
}

static OFC_BOOL 
OfcFSDarwinGetDiskFreeSpace (OFC_LPCTSTR lpRootPathName,
			     OFC_LPDWORD lpSectorsPerCluster,
			     OFC_LPDWORD lpBytesPerSector,
			     OFC_LPDWORD lpNumberOfFreeClusters,
			     OFC_LPDWORD lpTotalNumberOfClusters) 
{
  OFC_BOOL ret ;
  struct statfs fsstat ;
  int status ;
  OFC_CHAR *asciiPath ;

  asciiPath = FilePath2DarwinPath (lpRootPathName) ;
  status = statfs (asciiPath, &fsstat) ;
  BlueHeapFree (asciiPath) ;

  ret = OFC_FALSE ;
  if (status >= 0)
    {
      ret = OFC_TRUE ;
      *lpSectorsPerCluster = 1 ;
      *lpBytesPerSector = fsstat.f_bsize ;
      *lpNumberOfFreeClusters = (OFC_DWORD) fsstat.f_bavail ;
      *lpTotalNumberOfClusters = (OFC_DWORD) fsstat.f_blocks ;
    }
  else
    BlueThreadSetVariable (OfcLastError, 
			   (OFC_DWORD_PTR) TranslateError(errno)) ;

  return (ret) ;
}

static OFC_BOOL
OfcFSDarwinGetVolumeInformation (OFC_LPCTSTR lpRootPathName,
				 OFC_LPTSTR lpVolumeNameBuffer,
				 OFC_DWORD nVolumeNameSize,
				 OFC_LPDWORD lpVolumeSerialNumber,
				 OFC_LPDWORD lpMaximumComponentLength,
				 OFC_LPDWORD lpFileSystemFlags,
				 OFC_LPTSTR lpFileSystemName,
				 OFC_DWORD nFileSystemName) 
{
  OFC_BOOL ret ;
  struct statfs fsstat ;
  int status ;
  OFC_CHAR *asciiPath ;
  OFC_LPTSTR tcharPath ;

  asciiPath = FilePath2DarwinPath (lpRootPathName) ;
  status = statfs (asciiPath, &fsstat) ;
  BlueHeapFree (asciiPath) ;

  ret = OFC_FALSE ;
  if (status >= 0)
    {
      ret = OFC_TRUE ;
      if (lpFileSystemName != OFC_NULL)
	{
	  asciiPath = BlueHeapMalloc (MFSNAMELEN+1) ;
	  BlueCstrncpy (asciiPath, fsstat.f_fstypename, MFSNAMELEN) ;
	  asciiPath[MFSNAMELEN] = TCHAR_EOS ;
	  tcharPath = BlueCcstr2tstr (asciiPath) ;
	  BlueCtstrncpy (lpFileSystemName, tcharPath, nFileSystemName) ;
	  BlueHeapFree (tcharPath) ;
	  BlueHeapFree (asciiPath) ;
	}

      if (lpVolumeNameBuffer != OFC_NULL)
	{
	  asciiPath = BlueHeapMalloc (MNAMELEN+1) ;
	  BlueCstrncpy (asciiPath, fsstat.f_mntfromname, MNAMELEN) ;
	  asciiPath[MNAMELEN] = TCHAR_EOS ;
	  tcharPath = BlueCcstr2tstr (asciiPath) ;
	  BlueCtstrncpy (lpVolumeNameBuffer, tcharPath, nVolumeNameSize) ;
	  BlueHeapFree (tcharPath) ;
	  BlueHeapFree (asciiPath) ;
	}

      if (lpVolumeSerialNumber != OFC_NULL)
	*lpVolumeSerialNumber = fsstat.f_fsid.val[0] ;

      if (lpMaximumComponentLength != OFC_NULL)
	*lpMaximumComponentLength = MAXPATHLEN ;

      if (lpFileSystemFlags != OFC_NULL)
	*lpFileSystemFlags = fsstat.f_flags ;
    }
  else
    BlueThreadSetVariable (OfcLastError, 
			   (OFC_DWORD_PTR) TranslateError(errno)) ;

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
 * OFC_TRUE if successful, OFC_FALSE otherwise
 */
static OFC_BOOL OfcFSDarwinUnlockFileEx (OFC_HANDLE hFile,
                                         OFC_UINT32 length_low,
                                         OFC_UINT32 length_high,
                                         OFC_HANDLE hOverlapped)
{
  OFC_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  int status ;

  ret = OFC_FALSE ;
  context = ofc_handle_lock (hFile) ;

  if (context == OFC_NULL || context->backup)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      status = flock (context->fd, LOCK_UN) ;
      if (status == 0)
	ret = OFC_TRUE ;
      else
	BlueThreadSetVariable (OfcLastError, 
			       (OFC_DWORD_PTR) TranslateError(errno)) ;
    }

  if (context != OFC_NULL)
    ofc_handle_unlock (hFile) ;
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
 * OFC_TRUE if successful, OFC_FALSE otherwise
 */
static OFC_BOOL OfcFSDarwinLockFileEx (OFC_HANDLE hFile, OFC_DWORD flags,
                                       OFC_DWORD length_low,
                                       OFC_DWORD length_high,
                                       OFC_HANDLE lpOverlapped)
{
  OFC_BOOL ret ;
  BLUE_FS_DARWIN_CONTEXT *context ;
  int status ;
  int operation ;

  ret = OFC_FALSE ;
  context = ofc_handle_lock (hFile) ;

  if (context != OFC_NULL || context->backup)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      if (flags & OFC_LOCKFILE_EXCLUSIVE_LOCK)
	operation = LOCK_EX ;
      else
	operation = LOCK_SH ;
      if (flags & OFC_LOCKFILE_FAIL_IMMEDIATELY)
	operation |= LOCK_NB ;

      status = flock (context->fd, operation) ;
      if (status == 0)
	ret = OFC_TRUE ;
      else
	BlueThreadSetVariable (OfcLastError, 
			       (OFC_DWORD_PTR) TranslateError(errno)) ;
    }

  if (context != OFC_NULL)
    ofc_handle_unlock (hFile) ;

  return (ret) ;
}

static OFC_BOOL OfcFSDarwinDismount (OFC_LPCTSTR filename)
{
  OFC_BOOL ret ;

  ret = OFC_TRUE ;
  return (ret) ;
}

static OFC_FILE_FSINFO OfcFSDarwinInfo =
  {
    &OfcFSDarwinCreateFile,
    &OfcFSDarwinDeleteFile,
    &OfcFSDarwinFindFirstFile,
    &OfcFSDarwinFindNextFile,
    &OfcFSDarwinFindClose,
    &OfcFSDarwinFlushFileBuffers,
    &OfcFSDarwinGetFileAttributesEx,
    &OfcFSDarwinGetFileInformationByHandleEx,
    &OfcFSDarwinMoveFile,
    &OfcFSDarwinGetOverlappedResult,
    &OfcFSDarwinCreateOverlapped,
    &OfcFSDarwinDestroyOverlapped,
    &OfcFSDarwinSetOverlappedOffset,
    &OfcFSDarwinSetEndOfFile,
    &OfcFSDarwinSetFileAttributes,
    &OfcFSDarwinSetFileInformationByHandle,
    &OfcFSDarwinSetFilePointer,
    &OfcFSDarwinWriteFile,
    &OfcFSDarwinReadFile,
    &OfcFSDarwinCloseHandle,
    &OfcFSDarwinTransactNamedPipe,
    &OfcFSDarwinGetDiskFreeSpace,
    &OfcFSDarwinGetVolumeInformation,
    &OfcFSDarwinCreateDirectory,
    &OfcFSDarwinRemoveDirectory,
    &OfcFSDarwinUnlockFileEx,
    &OfcFSDarwinLockFileEx,
    &OfcFSDarwinDismount,
    OFC_NULL
  } ;

static OFC_DWORD 
OfcFSDarwinAIOThread (OFC_HANDLE hThread, OFC_VOID *context)
{
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;
  
  Overlapped = context ;

  while (!BlueThreadIsDeleting (hThread))
    {
      ofc_event_wait (Overlapped->hBusy) ;
      Overlapped->Errno = 0 ;
      if (Overlapped->opcode == BLUE_FSDARWIN_READ)
	{
	  Overlapped->dwResult = 
	    (OFC_INT) pread (Overlapped->fd,
			      (void *) Overlapped->lpBuffer,
			      Overlapped->nNumberOfBytes,
			      Overlapped->offset) ;

	}
      else if (Overlapped->opcode == BLUE_FSDARWIN_WRITE)
	{
	  Overlapped->dwResult = 
	    (OFC_INT) pwrite (Overlapped->fd,
			       (void *) Overlapped->lpBuffer,
			       Overlapped->nNumberOfBytes,
			       Overlapped->offset) ;
	}
      if (Overlapped->opcode != BLUE_FSDARWIN_NOOP)
	{
	  if (Overlapped->dwResult < 0)
	    Overlapped->Errno = errno ;
	  ofc_event_set (Overlapped->hEvent) ;
	}
    }
  return (0) ;
}

OFC_VOID BlueFSDarwinStartup (OFC_VOID)
{
  ofc_fs_register (OFC_FST_DARWIN, &OfcFSDarwinInfo) ;

  OfcFSDarwinAIOFreeQ = BlueQcreate() ;
  g_instance = 0 ;
}

OFC_VOID BlueFSDarwinShutdown (OFC_VOID)
{
  OFC_HANDLE hOverlapped ;
  BLUE_FSDARWIN_OVERLAPPED *Overlapped ;

  for (hOverlapped = (OFC_HANDLE) BlueQdequeue (OfcFSDarwinAIOFreeQ) ;
       hOverlapped != OFC_HANDLE_NULL ;
       hOverlapped = (OFC_HANDLE) BlueQdequeue (OfcFSDarwinAIOFreeQ))
    {
      Overlapped = ofc_handle_lock (hOverlapped) ;
      if (Overlapped != OFC_NULL)
	{
	  BlueThreadDelete (Overlapped->hThread);
	  Overlapped->opcode = BLUE_FSDARWIN_NOOP ;
	  ofc_event_set (Overlapped->hBusy) ;
	  BlueThreadWait (Overlapped->hThread);
	  
	  ofc_event_destroy(Overlapped->hEvent);
	  ofc_event_destroy(Overlapped->hBusy);
	  BlueHeapFree(Overlapped);
	  ofc_handle_destroy(hOverlapped);
	  ofc_handle_unlock(hOverlapped);
	}
    }
  BlueQdestroy(OfcFSDarwinAIOFreeQ);
  OfcFSDarwinAIOFreeQ = OFC_HANDLE_NULL;
}

int OfcFSDarwinGetFD (OFC_HANDLE hFile)
{
  int fd ;
  BLUE_FS_DARWIN_CONTEXT *context ;

  fd = -1 ;
  context = ofc_handle_lock (hFile) ;

  if (context == OFC_NULL || context->backup)
    {
      BlueThreadSetVariable (OfcLastError, 
			     (OFC_DWORD_PTR) TranslateError(EPERM)) ;
    }
  else
    {
      fd = context->fd ;
    }

  if (context != OFC_NULL)
    ofc_handle_unlock (hFile) ;

  return (fd) ;
}

/** \} */
