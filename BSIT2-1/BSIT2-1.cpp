// BSIT2-1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <lsalookup.h>
#include <LM.h>
#include <Ntsecapi.h>
#include <sddl.h>

void handleError(const char *message);
void EnumerateGroupsAndUsers();
LSA_HANDLE GetPolicyHandle();

typedef DWORD		(*NetLocalGroupEnumT)		(LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
typedef NTSTATUS	(*NetLocalGroupGetMembersT)	(LPCWSTR, LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD_PTR);
typedef DWORD		(*NetApiBufferFreeT)		(PVOID);
typedef BOOL		(*ConvertSidToStringSidWT)	(PSID,LPWSTR*);
typedef NTSTATUS	(*LsaLookupNames2T)			(LSA_HANDLE, ULONG, ULONG, PLSA_UNICODE_STRING, PLSA_REFERENCED_DOMAIN_LIST*, PLSA_TRANSLATED_SID2*);
typedef DWORD		(*NetUserSetInfoT)			(LPCWSTR, LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef	DWORD		(*NetLocalGroupSetInfoT)	(LPCWSTR, LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef DWORD		(*NetUserChangePasswordT)	(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
typedef DWORD		(*NetUserDelT)				(LPCWSTR, LPCWSTR);
typedef DWORD		(*NetUserAddT)				(LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef DWORD		(*NetLocalGroupDelMembersT)	(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
typedef NTSTATUS	(*LsaRemoveAccountRightsT)	(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG);
typedef NTSTATUS	(*LsaAddAccountRightsT)		(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG);
typedef DWORD		(*NetLocalGroupDelT)		(LPCWSTR, LPCWSTR);
typedef DWORD		(*NetLocalGroupAddT)		(LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef DWORD		(*NetLocalGroupAddMembersT)	(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);

bool InitLsaString(
	PLSA_UNICODE_STRING pLsaString,
	LPCWSTR pwszString
)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
		return FALSE;

	if (NULL != pwszString)
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
			return FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return TRUE;
}

int main()
{
	setlocale(LC_ALL, "Russian");
	printf( "Hello World!\n");
	EnumerateGroupsAndUsers();
	return 0;
}

void EnumerateGroupsAndUsers()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
		handleError("No such library Netapi32.dll");

	NetLocalGroupEnumT NetLocalGroupEnum = (NetLocalGroupEnumT)GetProcAddress(Netapi32, "NetLocalGroupEnum");
	if (NetLocalGroupEnum == NULL)
		handleError("No such function NetLocalGroupEnum");

	NetLocalGroupGetMembersT NetLocalGroupGetMembers = (NetLocalGroupGetMembersT)GetProcAddress(Netapi32, "NetLocalGroupGetMembers");
	if (NetLocalGroupGetMembers == NULL)
		handleError("No such function NetLocalGroupGetMembers");

	NetApiBufferFreeT NetApiBufferFree = (NetApiBufferFreeT)GetProcAddress(Netapi32, "NetApiBufferFree");
	if (NetApiBufferFree == NULL)
		handleError("No such function NetApiBufferFree");

	HMODULE Advapi32 = LoadLibrary(L"Advapi32.dll");
	if (Advapi32 == NULL)
		handleError("No such library Advapi32.dll");

	ConvertSidToStringSidWT ConvertSidToStringSidW = (ConvertSidToStringSidWT)GetProcAddress(Advapi32, "ConvertSidToStringSidW");
	if (ConvertSidToStringSidW == NULL)
		handleError("No such function ConvertSidToStringSid");

	LsaLookupNames2T LsaLookupNames2 = (LsaLookupNames2T)GetProcAddress(Advapi32, "LsaLookupNames2");
	if (LsaLookupNames2 == NULL)
		handleError("No such function LsaLookupNames2");

	PLOCALGROUP_INFO_0 pGroupsBuf;
	LOCALGROUP_MEMBERS_INFO_2 pUsersBuf[8000];
	DWORD groupsTotalentries = 0, usersTotalentries = 0;
	DWORD groupsEntriesread = 0, usersEntriesread = 0;
	DWORD_PTR groupsResumehandle = NULL, usersResumehandle = NULL;

	NetLocalGroupEnum(NULL, 0, (LPBYTE *)&pGroupsBuf, MAX_PREFERRED_LENGTH, &groupsEntriesread, &groupsTotalentries, &groupsResumehandle);

	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
	PLSA_TRANSLATED_SID2  sid;
	LSA_UNICODE_STRING pLsaString[100];
	LPWSTR userStringSid;
	LPWSTR groupStringSid;
	LPWSTR name[100];
	bool rc;
	NTSTATUS status;
	int i = 0;
	for (i = 0; i < groupsEntriesread; i++)
	{
		name[i] = (pGroupsBuf[i].lgrpi0_name);
		rc = InitLsaString(&pLsaString[i], name[i]);
	}
	status = LsaLookupNames2(GetPolicyHandle(), 0x80000000, groupsEntriesread, pLsaString, &ReferencedDomains, &sid);
	for (i = 0; i < groupsEntriesread; i++)
	{
		LPWSTR curname = name[i];
		if (status == 0)
		{
			rc = ConvertSidToStringSid(sid[i].Sid, &groupStringSid);
			if (rc)
			{
				wprintf(L"%s %s\n", curname, groupStringSid);
				status = NetLocalGroupGetMembers(NULL, curname, 2, (LPBYTE *)&pUsersBuf, 4096, &usersEntriesread, &usersTotalentries, &usersResumehandle);
				for (DWORD j = 0; j < usersEntriesread; j++)
				{
					rc = ConvertSidToStringSid(pUsersBuf[j].lgrmi2_sid, &userStringSid);
					if (rc)
					{
						wprintf(L"\t%s %s\n", pUsersBuf[j].lgrmi2_domainandname, userStringSid);
					}
				}
			}
		}
		//LocalFree(groupStringSid);

		//NetApiBufferFree(pUsersBuf);
	}

	NetApiBufferFree(pGroupsBuf);


	FreeLibrary(Netapi32);
	FreeLibrary(Advapi32);


}

//void EnumerateAccountRights()
//{
//	WCHAR name[127];
//	printf("Name: ");	_getws_s(name); \
//	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
//	PLSA_TRANSLATED_SID2  sid;
//	//LsaLookupNames2(GetPolicyHandle(), 0x80000000, 1, InitLsaString(name), &ReferencedDomains, &sid);
//	PLSA_UNICODE_STRING rights;
//	ULONG count;
//	//LsaEnumerateAccountRights(GetPolicyHandle(), sid, &rights, &count);
//	for (ULONG k = 0; k < count; k++)
//	{
//		wprintf(L"%s\n", rights->Buffer);
//	}
//}


void EnumerateAccountRightsToken()
{
	WCHAR username[127];
	WCHAR password[127];
	printf("User name: ");	_getws_s(username);
	printf("User password: "); _getws_s(password);
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
	PLSA_TRANSLATED_SID2  sid;
	//LsaLookupNames2(GetPolicyHandle(), 0x80000000, 1, InitLsaString(username), &ReferencedDomains, &sid);
	HANDLE token;
	TCHAR  privilegeName[256];
	DWORD PrivilegeName;
	if (!LogonUser(username, 0, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token))
	{
		printf("Error logon process\n");
		return;
	}
	DWORD dwLen = NULL;
	PTOKEN_PRIVILEGES priv = NULL;
	GetTokenInformation(token, TokenPrivileges, NULL, 0, &dwLen);
	priv = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen);
	if (!GetTokenInformation(token, TokenPrivileges, priv, dwLen, &dwLen))
	{
		printf("Error gettoken process\n");
		return;
	}
	for (DWORD i = 0; i < priv->PrivilegeCount; i++)
	{
		PrivilegeName = 256;
		LookupPrivilegeName(NULL, &priv->Privileges[i].Luid, (LPWSTR)privilegeName, &PrivilegeName);
		if ((priv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED || (priv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
			wprintf(L"%s\n", privilegeName);
	}
	HeapFree(GetProcessHeap(), 0, priv);
	CloseHandle(token);
}

LSA_HANDLE GetPolicyHandle()
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS ntsResult;
	LSA_HANDLE lsahPolicyHandle;

	// Object attributes are reserved, so initialize to zeros.
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	// Get a handle to the Policy object.
	ntsResult = LsaOpenPolicy(
		NULL,    //Name of the target system.
		&ObjectAttributes, //Object attributes.
		POLICY_ALL_ACCESS, //POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION, //Desired access permissions.
		&lsahPolicyHandle  //Receives the policy handle.
	);

	if (ntsResult != 0)
	{
		// An error occurred. Display it as a win32 error code.
		wprintf(L"OpenPolicy returned %lu\n",
			LsaNtStatusToWinError(ntsResult));
		return NULL;
	}
	return lsahPolicyHandle;
}

void ChangeUsername()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
		handleError("No such library Netapi32.dll");
	NetUserSetInfoT NetUserSetInfo = (NetUserSetInfoT)GetProcAddress(Netapi32, "NetUserSetInfo");
	if (NetUserSetInfo == NULL)
		handleError("No such function NetUserSetInfo");

	TCHAR username[100];
	TCHAR newusername[100];
	printf("User name: "); _getws_s(username);
	printf("New name: ");	_getws_s(newusername);
	USER_INFO_0 pBuf;
	pBuf.usri0_name = newusername;
	NET_API_STATUS dwerr = NetUserSetInfo(0, username, 0, (LPBYTE)&pBuf, 0);
	if (dwerr == 0) wprintf(L"user '%s' was changed to '%s' \n\n", username, newusername);
	else wprintf(L"error while changing user's general settings");
}

void ChangeUserpassword()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
		handleError("No such library Netapi32.dll");
	NetUserChangePasswordT NetUserChangePassword = (NetUserChangePasswordT)GetProcAddress(Netapi32, "NetUserChangePassword");
	if (NetUserChangePassword == NULL)
		handleError("No such function NetUserChangePassword");
	TCHAR username[100];
	TCHAR oldpass[100];
	TCHAR newpass[100];
	printf("User name: "); _getws_s(username);
	printf("User password: ");	_getws_s(oldpass);
	printf("New password: ");	_getws_s(newpass);
	DWORD dwError = 0;
	if (!NetUserChangePassword(NULL, username, oldpass, newpass))
		printf("NetUserChangePassword error\n");
}
void ChangeGroupname()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
		handleError("No such library Netapi32.dll");
	NetLocalGroupSetInfoT NetLocalGroupSetInfo = (NetLocalGroupSetInfoT)GetProcAddress(Netapi32, "NetLocalGroupSetInfo");
	if (NetLocalGroupSetInfo == NULL)
		handleError("No such function NetLocalGroupSetInfo");
	TCHAR groupname[100];
	TCHAR newname[100];
	printf("Group name: "); _getws_s(groupname);
	printf("New name: ");	_getws_s(newname);
	LOCALGROUP_INFO_0 lcgrstructure;
	lcgrstructure.lgrpi0_name = newname;
	if (NetLocalGroupSetInfo(0, groupname, 0, (LPBYTE)&lcgrstructure, 0))
		printf("NetLocalGroupSetInfo error\n");
}

void AddUser()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
		handleError("No such library Netapi32.dll");
	NetUserAddT NetUserAdd = (NetUserAddT)GetProcAddress(Netapi32, "NetUserAdd");
	if (NetUserAdd == NULL)
		handleError("No such function NetUserAdd");

	TCHAR username[100];
	TCHAR password[100];
	printf("User name: "); _getws_s(username);
	printf("User password: ");	_getws_s(password);
	USER_INFO_1 ui;
	ui.usri1_name = username;
	ui.usri1_password = password;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_NORMAL_ACCOUNT;
	ui.usri1_script_path = NULL;
	DWORD dwError = 0;
	if (NetUserAdd(0, 1, (LPBYTE)&ui, &dwError))
		printf("NetLocalGroupSetInfo error\n");
}
void DeleteUser()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
		handleError("No such library Netapi32.dll");
	NetUserDelT NetUserDel = (NetUserDelT)GetProcAddress(Netapi32, "NetUserDel");
	if (NetUserDel == NULL)
		handleError("No such function NetUserDel");

	WCHAR username[127];
	printf("User name: ");	_getws_s(username);
	if (NetUserDel(0, username))
		printf("NetLocalGroupSetInfo error\n");
}
void DeleteUserFromGroup()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
		handleError("No such library Netapi32.dll");
	NetLocalGroupDelMembersT NetLocalGroupDelMembers = (NetLocalGroupDelMembersT)GetProcAddress(Netapi32, "NetLocalGroupDelMembers");
	if (NetLocalGroupDelMembers == NULL)
		handleError("No such function NetLocalGroupDelMembers");

	WCHAR username[127];
	WCHAR groupname[127];
	printf("User name: ");	_getws_s(username);
	printf("Group name: ");	_getws_s(groupname);
	LOCALGROUP_MEMBERS_INFO_3 lgmi3;
	lgmi3.lgrmi3_domainandname = username;
	if (NetLocalGroupDelMembers(0, groupname, 3, (LPBYTE)&lgmi3, 1))
		printf("NetLocalGroupDelMembers error\n");
}
void AddNewUserToGroup()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
		handleError("No such library Netapi32.dll");
	NetLocalGroupAddMembersT NetLocalGroupAddMembers = (NetLocalGroupAddMembersT)GetProcAddress(Netapi32, "NetLocalGroupAddMembers");
	if (NetLocalGroupAddMembers == NULL)
		handleError("No such function NetLocalGroupAddMembers");

	WCHAR username[127];
	WCHAR groupname[127];
	printf("User name: ");	_getws_s(username);
	printf("Group name: ");	_getws_s(groupname);
	LOCALGROUP_MEMBERS_INFO_3 lgmi3;
	lgmi3.lgrmi3_domainandname = username;
	if (NetLocalGroupAddMembers(0, groupname, 3, (LPBYTE)&lgmi3, 1))
		printf("NetLocalGroupAddMembers error\n");

}
void AddGroup()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
		handleError("No such library Netapi32.dll");
	NetLocalGroupAddT NetLocalGroupAdd = (NetLocalGroupAddT)GetProcAddress(Netapi32, "NetLocalGroupAdd");
	if (NetLocalGroupAdd == NULL)
		handleError("No such function NetLocalGroupAdd");

	WCHAR groupname[127];
	printf("Group name: ");	_getws_s(groupname);
	_LOCALGROUP_INFO_0 lgi;
	lgi.lgrpi0_name = groupname;
	if (NetLocalGroupAdd(0, 0, (LPBYTE)&lgi, 0))
		printf("NetLocalGroupAdd error\n");
}

void DeleteGroup()
{
	HMODULE Netapi32 = LoadLibrary(L"Netapi32.dll");
	if (Netapi32 == NULL)
		handleError("No such library Netapi32.dll");
	NetLocalGroupDelT NetLocalGroupDel = (NetLocalGroupDelT)GetProcAddress(Netapi32, "NetLocalGroupDel");
	if (NetLocalGroupDel == NULL)
		handleError("No such function NetLocalGroupDel");

	WCHAR groupname[127];
	printf("Group name: ");	_getws_s(groupname);
	if (NetLocalGroupDel(0, groupname))
		printf("NetLocalGroupDel error\n");
}


void DeleteAccountRights()
{
	HMODULE Advapi32 = LoadLibrary(L"Advapi32.dll");
	if (Advapi32 == NULL)
		handleError("No such library Netapi32.dll");
	LsaLookupNames2T LsaLookupNames2 = (LsaLookupNames2T)GetProcAddress(Advapi32, "LsaLookupNames2");
	if (LsaLookupNames2 == NULL)
		handleError("No such function LsaLookupNames2");
	LsaRemoveAccountRightsT LsaRemoveAccountRights = (LsaRemoveAccountRightsT)GetProcAddress(Advapi32, "LsaRemoveAccountRights");
	if (LsaRemoveAccountRights == NULL)
		handleError("No such function LsaRemoveAccountRights");
	LsaAddAccountRightsT LsaAddAccountRights = (LsaAddAccountRightsT)GetProcAddress(Advapi32, "LsaAddAccountRights");
	if (LsaAddAccountRights == NULL)
		handleError("No such function LsaAddAccountRights");

	WCHAR name[127];
	WCHAR privname[127];
	printf("Name: ");	_getws_s(name);
	printf("Access right: "); _getws_s(privname);
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
	PLSA_TRANSLATED_SID2  sid;
	//LsaLookupNames2(GetPolicyHandle(), 0x80000000, 1, InitLsaString(name), &ReferencedDomains, &sid);
	//LsaRemoveAccountRights(GetPolicyHandle(), sid, 0, InitLsaString(privname), 1);
	//LsaAddAccountRights(GetPolicyHandle(), sid, InitLsaString(privname), 1);
}

void AddAccountRights()
{
	HMODULE Advapi32 = LoadLibrary(L"Advapi32.dll");
	if (Advapi32 == NULL)
		handleError("No such library Netapi32.dll");
	LsaLookupNames2T LsaLookupNames2 = (LsaLookupNames2T)GetProcAddress(Advapi32, "LsaLookupNames2");
	if (LsaLookupNames2 == NULL)
		handleError("No such function LsaLookupNames2");
	LsaAddAccountRightsT LsaAddAccountRights = (LsaAddAccountRightsT)GetProcAddress(Advapi32, "LsaAddAccountRights");
	if (LsaAddAccountRights == NULL)
		handleError("No such function LsaAddAccountRights");

	WCHAR name[127];
	WCHAR privname[127];
	printf("Name: ");	_getws_s(name);
	printf("Access right: "); _getws_s(privname);
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
	PLSA_TRANSLATED_SID2  sid;
	//LsaLookupNames2(GetPolicyHandle(), 0x80000000, 1, InitLsaString(name), &ReferencedDomains, &sid);
	//if (LsaAddAccountRights(GetPolicyHandle(), sid, InitLsaString(privname), 1))
	//	printf("LsaAddAccountRights error\n");
}

void handleError(const char *message)
{
	printf("Error: %s\n", message);
	exit(1);
}
