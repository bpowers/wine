/*
 * Unit test suite for directory functions.
 *
 * Copyright 2002 Dmitry Timoshkov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "wine/test.h"
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "aclapi.h"

static DWORD (WINAPI *pGetNamedSecurityInfoA)(LPSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION,
                                              PSID*, PSID*, PACL*, PACL*,
                                              PSECURITY_DESCRIPTOR*);
static BOOL (WINAPI *pGetAclInformation)(PACL,LPVOID,DWORD,ACL_INFORMATION_CLASS);
static BOOL (WINAPI *pCreateWellKnownSid)(WELL_KNOWN_SID_TYPE,PSID,PSID,DWORD*);
static BOOL (WINAPI *pAddAccessAllowedAceEx)(PACL, DWORD, DWORD, DWORD, PSID);
static BOOL (WINAPI *pGetAce)(PACL,DWORD,LPVOID*);

/* If you change something in these tests, please do the same
 * for GetSystemDirectory tests.
 */
static void test_GetWindowsDirectoryA(void)
{
    UINT len, len_with_null;
    char buf[MAX_PATH];

    len_with_null = GetWindowsDirectoryA(NULL, 0);
    ok(len_with_null <= MAX_PATH, "should fit into MAX_PATH\n");

    lstrcpyA(buf, "foo");
    len_with_null = GetWindowsDirectoryA(buf, 1);
    ok(lstrcmpA(buf, "foo") == 0, "should not touch the buffer\n");

    lstrcpyA(buf, "foo");
    len = GetWindowsDirectoryA(buf, len_with_null - 1);
    ok(lstrcmpA(buf, "foo") == 0, "should not touch the buffer\n");
    ok(len == len_with_null, "GetWindowsDirectoryW returned %d, expected %d\n",
       len, len_with_null);

    lstrcpyA(buf, "foo");
    len = GetWindowsDirectoryA(buf, len_with_null);
    ok(lstrcmpA(buf, "foo") != 0, "should touch the buffer\n");
    ok(len == strlen(buf), "returned length should be equal to the length of string\n");
    ok(len == len_with_null-1, "GetWindowsDirectoryA returned %d, expected %d\n",
       len, len_with_null-1);
}

static void test_GetWindowsDirectoryW(void)
{
    UINT len, len_with_null;
    WCHAR buf[MAX_PATH];
    static const WCHAR fooW[] = {'f','o','o',0};

    len_with_null = GetWindowsDirectoryW(NULL, 0);
    if (len_with_null == 0 && GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
    {
        win_skip("GetWindowsDirectoryW is not implemented\n");
        return;
    }
    ok(len_with_null <= MAX_PATH, "should fit into MAX_PATH\n");

    lstrcpyW(buf, fooW);
    len = GetWindowsDirectoryW(buf, 1);
    ok(lstrcmpW(buf, fooW) == 0, "should not touch the buffer\n");
    ok(len == len_with_null, "GetWindowsDirectoryW returned %d, expected %d\n",
       len, len_with_null);

    lstrcpyW(buf, fooW);
    len = GetWindowsDirectoryW(buf, len_with_null - 1);
    ok(lstrcmpW(buf, fooW) == 0, "should not touch the buffer\n");
    ok(len == len_with_null, "GetWindowsDirectoryW returned %d, expected %d\n",
       len, len_with_null);

    lstrcpyW(buf, fooW);
    len = GetWindowsDirectoryW(buf, len_with_null);
    ok(lstrcmpW(buf, fooW) != 0, "should touch the buffer\n");
    ok(len == lstrlenW(buf), "returned length should be equal to the length of string\n");
    ok(len == len_with_null-1, "GetWindowsDirectoryW returned %d, expected %d\n",
       len, len_with_null-1);
}


/* If you change something in these tests, please do the same
 * for GetWindowsDirectory tests.
 */
static void test_GetSystemDirectoryA(void)
{
    UINT len, len_with_null;
    char buf[MAX_PATH];

    len_with_null = GetSystemDirectoryA(NULL, 0);
    ok(len_with_null <= MAX_PATH, "should fit into MAX_PATH\n");

    lstrcpyA(buf, "foo");
    len = GetSystemDirectoryA(buf, 1);
    ok(lstrcmpA(buf, "foo") == 0, "should not touch the buffer\n");
    ok(len == len_with_null, "GetSystemDirectoryA returned %d, expected %d\n",
       len, len_with_null);

    lstrcpyA(buf, "foo");
    len = GetSystemDirectoryA(buf, len_with_null - 1);
    ok(lstrcmpA(buf, "foo") == 0, "should not touch the buffer\n");
    ok(len == len_with_null, "GetSystemDirectoryA returned %d, expected %d\n",
       len, len_with_null);

    lstrcpyA(buf, "foo");
    len = GetSystemDirectoryA(buf, len_with_null);
    ok(lstrcmpA(buf, "foo") != 0, "should touch the buffer\n");
    ok(len == strlen(buf), "returned length should be equal to the length of string\n");
    ok(len == len_with_null-1, "GetSystemDirectoryW returned %d, expected %d\n",
       len, len_with_null-1);
}

static void test_GetSystemDirectoryW(void)
{
    UINT len, len_with_null;
    WCHAR buf[MAX_PATH];
    static const WCHAR fooW[] = {'f','o','o',0};

    len_with_null = GetSystemDirectoryW(NULL, 0);
    if (len_with_null == 0 && GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
    {
        win_skip("GetSystemDirectoryW is not available\n");
        return;
    }
    ok(len_with_null <= MAX_PATH, "should fit into MAX_PATH\n");

    lstrcpyW(buf, fooW);
    len = GetSystemDirectoryW(buf, 1);
    ok(lstrcmpW(buf, fooW) == 0, "should not touch the buffer\n");
    ok(len == len_with_null, "GetSystemDirectoryW returned %d, expected %d\n",
       len, len_with_null);

    lstrcpyW(buf, fooW);
    len = GetSystemDirectoryW(buf, len_with_null - 1);
    ok(lstrcmpW(buf, fooW) == 0, "should not touch the buffer\n");
    ok(len == len_with_null, "GetSystemDirectoryW returned %d, expected %d\n",
       len, len_with_null);

    lstrcpyW(buf, fooW);
    len = GetSystemDirectoryW(buf, len_with_null);
    ok(lstrcmpW(buf, fooW) != 0, "should touch the buffer\n");
    ok(len == lstrlenW(buf), "returned length should be equal to the length of string\n");
    ok(len == len_with_null-1, "GetSystemDirectoryW returned %d, expected %d\n",
       len, len_with_null-1);
}

static void test_CreateDirectoryA(void)
{
    char tmpdir[MAX_PATH];
    BOOL ret;

    ret = CreateDirectoryA(NULL, NULL);
    ok(ret == FALSE && (GetLastError() == ERROR_PATH_NOT_FOUND ||
                        GetLastError() == ERROR_INVALID_PARAMETER),
       "CreateDirectoryA(NULL): ret=%d err=%d\n", ret, GetLastError());

    ret = CreateDirectoryA("", NULL);
    ok(ret == FALSE && (GetLastError() == ERROR_BAD_PATHNAME ||
                        GetLastError() == ERROR_PATH_NOT_FOUND),
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());

    ret = GetSystemDirectoryA(tmpdir, MAX_PATH);
    ok(ret < MAX_PATH, "System directory should fit into MAX_PATH\n");

    ret = SetCurrentDirectoryA(tmpdir);
    ok(ret == TRUE, "could not chdir to the System directory\n");

    ret = CreateDirectoryA(".", NULL);
    ok(ret == FALSE && GetLastError() == ERROR_ALREADY_EXISTS,
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());


    ret = CreateDirectoryA("..", NULL);
    ok(ret == FALSE && GetLastError() == ERROR_ALREADY_EXISTS,
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());

    GetTempPathA(MAX_PATH, tmpdir);
    tmpdir[3] = 0; /* truncate the path */
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == FALSE && (GetLastError() == ERROR_ALREADY_EXISTS ||
                        GetLastError() == ERROR_ACCESS_DENIED),
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());

    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == TRUE,       "CreateDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());

    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == FALSE && GetLastError() == ERROR_ALREADY_EXISTS,
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());

    ret = RemoveDirectoryA(tmpdir);
    ok(ret == TRUE,
       "RemoveDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());


    lstrcatA(tmpdir, "?");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == FALSE && (GetLastError() == ERROR_INVALID_NAME ||
			GetLastError() == ERROR_PATH_NOT_FOUND),
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());
    RemoveDirectoryA(tmpdir);

    tmpdir[lstrlenA(tmpdir) - 1] = '*';
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == FALSE && (GetLastError() == ERROR_INVALID_NAME ||
			GetLastError() == ERROR_PATH_NOT_FOUND),
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());
    RemoveDirectoryA(tmpdir);

    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me/Please Remove Me");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == FALSE && GetLastError() == ERROR_PATH_NOT_FOUND, 
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());
    RemoveDirectoryA(tmpdir);

    /* Test behavior with a trailing dot.
     * The directory should be created without the dot.
     */
    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me.");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == TRUE,
       "CreateDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());

    lstrcatA(tmpdir, "/Please Remove Me");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == TRUE,
       "CreateDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());
    ret = RemoveDirectoryA(tmpdir);
    ok(ret == TRUE,
       "RemoveDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());

    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me");
    ret = RemoveDirectoryA(tmpdir);
    ok(ret == TRUE,
       "RemoveDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());

    /* Test behavior with two trailing dots.
     * The directory should be created without the trailing dots.
     */
    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me..");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == TRUE,
       "CreateDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());

    lstrcatA(tmpdir, "/Please Remove Me");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == TRUE || /* On Win98 */
       (ret == FALSE && GetLastError() == ERROR_PATH_NOT_FOUND), /* On NT! */
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());
    if (ret == TRUE)
    {
        ret = RemoveDirectoryA(tmpdir);
        ok(ret == TRUE,
           "RemoveDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());
    }

    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me");
    ret = RemoveDirectoryA(tmpdir);
    ok(ret == TRUE,
       "RemoveDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());

    /* Test behavior with a trailing space.
     * The directory should be created without the trailing space.
     */
    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me ");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == TRUE,
       "CreateDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());

    lstrcatA(tmpdir, "/Please Remove Me");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == TRUE || /* On Win98 */
       (ret == FALSE && GetLastError() == ERROR_PATH_NOT_FOUND), /* On NT! */
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());
    if (ret == TRUE)
    {
        ret = RemoveDirectoryA(tmpdir);
        ok(ret == TRUE,
           "RemoveDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());
    }

    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me");
    ret = RemoveDirectoryA(tmpdir);
    ok(ret == TRUE,
       "RemoveDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());

    /* Test behavior with a trailing space.
     * The directory should be created without the trailing spaces.
     */
    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me  ");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == TRUE,
       "CreateDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());

    lstrcatA(tmpdir, "/Please Remove Me");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == TRUE || /* On Win98 */
       (ret == FALSE && GetLastError() == ERROR_PATH_NOT_FOUND), /* On NT! */
       "CreateDirectoryA(%s): ret=%d err=%d\n", tmpdir, ret, GetLastError());
    if (ret == TRUE)
    {
        ret = RemoveDirectoryA(tmpdir);
        ok(ret == TRUE,
           "RemoveDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());
    }

    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me");
    ret = RemoveDirectoryA(tmpdir);
    ok(ret == TRUE,
       "RemoveDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());
}

static void test_CreateDirectoryW(void)
{
    WCHAR tmpdir[MAX_PATH];
    BOOL ret;
    static const WCHAR empty_strW[] = { 0 };
    static const WCHAR tmp_dir_name[] = {'P','l','e','a','s','e',' ','R','e','m','o','v','e',' ','M','e',0};
    static const WCHAR dotW[] = {'.',0};
    static const WCHAR slashW[] = {'/',0};
    static const WCHAR dotdotW[] = {'.','.',0};
    static const WCHAR questionW[] = {'?',0};

    ret = CreateDirectoryW(NULL, NULL);
    if (!ret && GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
    {
        win_skip("CreateDirectoryW is not available\n");
        return;
    }
    ok(ret == FALSE && GetLastError() == ERROR_PATH_NOT_FOUND,
       "should not create NULL path ret %u err %u\n", ret, GetLastError());

    ret = CreateDirectoryW(empty_strW, NULL);
    ok(ret == FALSE && GetLastError() == ERROR_PATH_NOT_FOUND,
       "should not create empty path ret %u err %u\n", ret, GetLastError());

    ret = GetSystemDirectoryW(tmpdir, MAX_PATH);
    ok(ret < MAX_PATH, "System directory should fit into MAX_PATH\n");

    ret = SetCurrentDirectoryW(tmpdir);
    ok(ret == TRUE, "could not chdir to the System directory ret %u err %u\n", ret, GetLastError());

    ret = CreateDirectoryW(dotW, NULL);
    ok(ret == FALSE && GetLastError() == ERROR_ALREADY_EXISTS,
       "should not create existing path ret %u err %u\n", ret, GetLastError());

    ret = CreateDirectoryW(dotdotW, NULL);
    ok(ret == FALSE && GetLastError() == ERROR_ALREADY_EXISTS,
       "should not create existing path ret %u err %u\n", ret, GetLastError());

    GetTempPathW(MAX_PATH, tmpdir);
    tmpdir[3] = 0; /* truncate the path */
    ret = CreateDirectoryW(tmpdir, NULL);
    ok(ret == FALSE && (GetLastError() == ERROR_ACCESS_DENIED || GetLastError() == ERROR_ALREADY_EXISTS),
       "should deny access to the drive root ret %u err %u\n", ret, GetLastError());

    GetTempPathW(MAX_PATH, tmpdir);
    lstrcatW(tmpdir, tmp_dir_name);
    ret = CreateDirectoryW(tmpdir, NULL);
    ok(ret == TRUE, "CreateDirectoryW should always succeed\n");

    ret = CreateDirectoryW(tmpdir, NULL);
    ok(ret == FALSE && GetLastError() == ERROR_ALREADY_EXISTS,
       "should not create existing path ret %u err %u\n", ret, GetLastError());

    ret = RemoveDirectoryW(tmpdir);
    ok(ret == TRUE, "RemoveDirectoryW should always succeed\n");

    lstrcatW(tmpdir, questionW);
    ret = CreateDirectoryW(tmpdir, NULL);
    ok(ret == FALSE && GetLastError() == ERROR_INVALID_NAME,
       "CreateDirectoryW with ? wildcard name should fail with error 183, ret=%s error=%d\n",
       ret ? " True" : "False", GetLastError());
    ret = RemoveDirectoryW(tmpdir);
    ok(ret == FALSE, "RemoveDirectoryW should have failed\n");

    tmpdir[lstrlenW(tmpdir) - 1] = '*';
    ret = CreateDirectoryW(tmpdir, NULL);
    ok(ret == FALSE && GetLastError() == ERROR_INVALID_NAME,
       "CreateDirectoryW with * wildcard name should fail with error 183, ret=%s error=%d\n",
       ret ? " True" : "False", GetLastError());
    ret = RemoveDirectoryW(tmpdir);
    ok(ret == FALSE, "RemoveDirectoryW should have failed\n");
    
    GetTempPathW(MAX_PATH, tmpdir);
    lstrcatW(tmpdir, tmp_dir_name);
    lstrcatW(tmpdir, slashW);
    lstrcatW(tmpdir, tmp_dir_name);
    ret = CreateDirectoryW(tmpdir, NULL);
    ok(ret == FALSE && GetLastError() == ERROR_PATH_NOT_FOUND,
      "CreateDirectoryW with multiple nonexistent directories in path should fail ret %u err %u\n",
       ret, GetLastError());
    ret = RemoveDirectoryW(tmpdir);
    ok(ret == FALSE, "RemoveDirectoryW should have failed\n");
}

static void test_RemoveDirectoryA(void)
{
    char tmpdir[MAX_PATH];
    BOOL ret;

    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me");
    ret = CreateDirectoryA(tmpdir, NULL);
    ok(ret == TRUE, "CreateDirectoryA should always succeed\n");

    ret = RemoveDirectoryA(tmpdir);
    ok(ret == TRUE, "RemoveDirectoryA should always succeed\n");

    lstrcatA(tmpdir, "?");
    ret = RemoveDirectoryA(tmpdir);
    ok(ret == FALSE && (GetLastError() == ERROR_INVALID_NAME ||
			GetLastError() == ERROR_PATH_NOT_FOUND),
       "RemoveDirectoryA with ? wildcard name should fail, ret=%s error=%d\n",
       ret ? " True" : "False", GetLastError());

    tmpdir[lstrlenA(tmpdir) - 1] = '*';
    ret = RemoveDirectoryA(tmpdir);
    ok(ret == FALSE && (GetLastError() == ERROR_INVALID_NAME ||
			GetLastError() == ERROR_PATH_NOT_FOUND),
       "RemoveDirectoryA with * wildcard name should fail, ret=%s error=%d\n",
       ret ? " True" : "False", GetLastError());
}

static void test_RemoveDirectoryW(void)
{
    WCHAR tmpdir[MAX_PATH];
    BOOL ret;
    static const WCHAR tmp_dir_name[] = {'P','l','e','a','s','e',' ','R','e','m','o','v','e',' ','M','e',0};
    static const WCHAR questionW[] = {'?',0};

    GetTempPathW(MAX_PATH, tmpdir);
    lstrcatW(tmpdir, tmp_dir_name);
    ret = CreateDirectoryW(tmpdir, NULL);
    if (!ret && GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
    {
        win_skip("CreateDirectoryW is not available\n");
        return;
    }

    ok(ret == TRUE, "CreateDirectoryW should always succeed\n");

    ret = RemoveDirectoryW(tmpdir);
    ok(ret == TRUE, "RemoveDirectoryW should always succeed\n");

    lstrcatW(tmpdir, questionW);
    ret = RemoveDirectoryW(tmpdir);
    ok(ret == FALSE && GetLastError() == ERROR_INVALID_NAME,
       "RemoveDirectoryW with wildcard should fail with error 183, ret=%s error=%d\n",
       ret ? " True" : "False", GetLastError());

    tmpdir[lstrlenW(tmpdir) - 1] = '*';
    ret = RemoveDirectoryW(tmpdir);
    ok(ret == FALSE && GetLastError() == ERROR_INVALID_NAME,
       "RemoveDirectoryW with * wildcard name should fail with error 183, ret=%s error=%d\n",
       ret ? " True" : "False", GetLastError());
}

static void test_SetCurrentDirectoryA(void)
{
    SetLastError(0);
    ok( !SetCurrentDirectoryA( "\\some_dummy_dir" ), "SetCurrentDirectoryA succeeded\n" );
    ok( GetLastError() == ERROR_FILE_NOT_FOUND, "wrong error %d\n", GetLastError() );
    ok( !SetCurrentDirectoryA( "\\some_dummy\\subdir" ), "SetCurrentDirectoryA succeeded\n" );
    ok( GetLastError() == ERROR_PATH_NOT_FOUND, "wrong error %d\n", GetLastError() );
}

static void test_security_attributes(void)
{
    char admin_ptr[sizeof(SID)+sizeof(ULONG)*SID_MAX_SUB_AUTHORITIES], dacl[100], *user;
    DWORD sid_size = sizeof(admin_ptr), user_size;
    PSID admin_sid = (PSID) admin_ptr, user_sid;
    char sd[SECURITY_DESCRIPTOR_MIN_LENGTH];
    PSECURITY_DESCRIPTOR pSD = &sd;
    ACL_SIZE_INFORMATION acl_size;
    PACL pDacl = (PACL) &dacl;
    ACCESS_ALLOWED_ACE *ace;
    SECURITY_ATTRIBUTES sa;
    char tmpfile[MAX_PATH];
    char tmpdir[MAX_PATH];
    HANDLE token, hTemp;
    struct _SID *owner;
    BOOL bret = TRUE;
    DWORD error;

    if (!pGetNamedSecurityInfoA || !pCreateWellKnownSid)
    {
        win_skip("Required functions are not available\n");
        return;
    }

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_READ, TRUE, &token))
    {
        if (GetLastError() != ERROR_NO_TOKEN) bret = FALSE;
        else if (!OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &token)) bret = FALSE;
    }
    if (!bret)
    {
        win_skip("Failed to get current user token\n");
        return;
    }
    bret = GetTokenInformation(token, TokenUser, NULL, 0, &user_size);
    ok(!bret && (GetLastError() == ERROR_INSUFFICIENT_BUFFER),
        "GetTokenInformation(TokenUser) failed with error %d\n", GetLastError());
    user = HeapAlloc(GetProcessHeap(), 0, user_size);
    bret = GetTokenInformation(token, TokenUser, user, user_size, &user_size);
    ok(bret, "GetTokenInformation(TokenUser) failed with error %d\n", GetLastError());
    CloseHandle( token );
    user_sid = ((TOKEN_USER *)user)->User.Sid;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = TRUE;
    InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
    pCreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin_sid, &sid_size);
    bret = InitializeAcl(pDacl, sizeof(dacl), ACL_REVISION);
    ok(bret, "Failed to initialize ACL.\n");
    bret = pAddAccessAllowedAceEx(pDacl, ACL_REVISION, OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE,
                                  GENERIC_ALL, user_sid);
    ok(bret, "Failed to add Current User to ACL.\n");
    bret = pAddAccessAllowedAceEx(pDacl, ACL_REVISION, OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE,
                                  GENERIC_ALL, admin_sid);
    ok(bret, "Failed to add Administrator Group to ACL.\n");
    bret = SetSecurityDescriptorDacl(pSD, TRUE, pDacl, FALSE);
    ok(bret, "Failed to add ACL to security desciptor.\n");

    GetTempPathA(MAX_PATH, tmpdir);
    lstrcatA(tmpdir, "Please Remove Me");
    bret = CreateDirectoryA(tmpdir, &sa);
    ok(bret == TRUE, "CreateDirectoryA(%s) failed err=%d\n", tmpdir, GetLastError());

    SetLastError(0xdeadbeef);
    error = pGetNamedSecurityInfoA(tmpdir, SE_FILE_OBJECT,
                                   OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION, (PSID*)&owner,
                                   NULL, &pDacl, NULL, &pSD);
    if (error != ERROR_SUCCESS && (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED))
    {
        win_skip("GetNamedSecurityInfoA is not implemented\n");
        goto done;
    }
    ok(!error, "GetNamedSecurityInfo failed with error %d\n", error);

    bret = pGetAclInformation(pDacl, &acl_size, sizeof(acl_size), AclSizeInformation);
    ok(bret, "GetAclInformation failed\n");
    ok(acl_size.AceCount == 2, "GetAclInformation returned unexpected entry count (%d != 2).\n",
                               acl_size.AceCount);
    if (acl_size.AceCount > 0)
    {
        bret = pGetAce(pDacl, 0, (VOID **)&ace);
        ok(bret, "Failed to get Current User ACE.\n");
        bret = EqualSid(&ace->SidStart, user_sid);
        ok(bret, "Current User ACE != Current User SID.\n");
        ok(((ACE_HEADER *)ace)->AceFlags == (OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE),
           "Current User ACE has unexpected flags (0x%x != 0x03)\n", ((ACE_HEADER *)ace)->AceFlags);
        ok(ace->Mask == 0x1f01ff, "Current User ACE has unexpected mask (0x%x != 0x1f01ff)\n",
                                  ace->Mask);
    }
    if (acl_size.AceCount > 1)
    {
        bret = pGetAce(pDacl, 1, (VOID **)&ace);
        ok(bret, "Failed to get Administators Group ACE.\n");
        bret = EqualSid(&ace->SidStart, admin_sid);
        ok(bret, "Administators Group ACE != Administators Group SID.\n");
        ok(((ACE_HEADER *)ace)->AceFlags == (OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE),
           "Administators Group ACE has unexpected flags (0x%x != 0x03)\n", ((ACE_HEADER *)ace)->AceFlags);
        ok(ace->Mask == 0x1f01ff, "Administators Group ACE has unexpected mask (0x%x != 0x1f01ff)\n",
                                  ace->Mask);
    }

    /* Test inheritance of ACLs */
    strcpy(tmpfile, tmpdir);
    lstrcatA(tmpfile, "/tmpfile");
    hTemp = CreateFileA(tmpfile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                        FILE_FLAG_DELETE_ON_CLOSE, NULL);
    error = pGetNamedSecurityInfoA(tmpfile, SE_FILE_OBJECT,
                                   OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION, (PSID*)&owner,
                                   NULL, &pDacl, NULL, &pSD);
    ok(error == ERROR_SUCCESS, "Failed to get permissions on file.\n");
    bret = pGetAclInformation(pDacl, &acl_size, sizeof(acl_size), AclSizeInformation);
    ok(bret, "GetAclInformation failed\n");
    ok(acl_size.AceCount == 2, "GetAclInformation returned unexpected entry count (%d != 2).\n",
                               acl_size.AceCount);
    if (acl_size.AceCount > 0)
    {
        bret = pGetAce(pDacl, 0, (VOID **)&ace);
        ok(bret, "Inherited Failed to get Current User ACE.\n");
        bret = EqualSid(&ace->SidStart, user_sid);
        ok(bret, "Inherited Current User ACE != Current User SID.\n");
        ok(((ACE_HEADER *)ace)->AceFlags == INHERITED_ACE,
           "Inherited Current User ACE has unexpected flags (0x%x != 0x10)\n", ((ACE_HEADER *)ace)->AceFlags);
        ok(ace->Mask == 0x1f01ff, "Current User ACE has unexpected mask (0x%x != 0x1f01ff)\n",
                                  ace->Mask);
    }
    if (acl_size.AceCount > 1)
    {
        bret = pGetAce(pDacl, 1, (VOID **)&ace);
        ok(bret, "Inherited Failed to get Administators Group ACE.\n");
        bret = EqualSid(&ace->SidStart, admin_sid);
        ok(bret, "Inherited Administators Group ACE != Administators Group SID.\n");
        ok(((ACE_HEADER *)ace)->AceFlags == INHERITED_ACE,
           "Inherited Administators Group ACE has unexpected flags (0x%x != 0x10)\n", ((ACE_HEADER *)ace)->AceFlags);
        ok(ace->Mask == 0x1f01ff, "Administators Group ACE has unexpected mask (0x%x != 0x1f01ff)\n",
                                  ace->Mask);
    }
    CloseHandle(hTemp);

done:
    HeapFree(GetProcessHeap(), 0, user);
    bret = RemoveDirectoryA(tmpdir);
    ok(bret == TRUE, "RemoveDirectoryA should always succeed\n");
}

void init(void)
{
    HMODULE hmod = GetModuleHandle("advapi32.dll");

    pGetNamedSecurityInfoA = (void *)GetProcAddress(hmod, "GetNamedSecurityInfoA");
    pAddAccessAllowedAceEx = (void *)GetProcAddress(hmod, "AddAccessAllowedAceEx");
    pCreateWellKnownSid = (void *)GetProcAddress(hmod, "CreateWellKnownSid");
    pGetAclInformation = (void *)GetProcAddress(hmod, "GetAclInformation");
    pGetAce = (void *)GetProcAddress(hmod, "GetAce");
}

START_TEST(directory)
{
    init();

    test_GetWindowsDirectoryA();
    test_GetWindowsDirectoryW();

    test_GetSystemDirectoryA();
    test_GetSystemDirectoryW();

    test_CreateDirectoryA();
    test_CreateDirectoryW();

    test_RemoveDirectoryA();
    test_RemoveDirectoryW();

    test_SetCurrentDirectoryA();

    test_security_attributes();
}
