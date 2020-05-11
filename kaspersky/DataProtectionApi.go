/*
 *
 * 	Copyright (C) 2020  <Semchenko Aleksandr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.If not, see <http://www.gnu.org/licenses/>.
 * /
 */

package kaspersky

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
)

//	DataProtectionApi Class Reference
//
//	Allows to protect sensitive data in policies, tasks, and/or on specified host.
//
//	List of all members.
type DataProtectionApi service

//	Checks if Spl password policy compliance is enabled for the specified Administration Server
//	and checks the specified password for compliance to the password policy.
//
//	Password Policy is specified below
//
//	Characters allowed:
//
//	A – Z
//	a – z
//	0 – 9
//	@ # $ % ^ & * - _ ! + = [ ] { } | \ : ‘ , . ? / ` ~ “ ( ) ;
//
//	Characters disallowed:
//
//	- Unicode characters
//	- spaces
//	- Cannot contain a dot character '.' immediately preceding the '@' symbol
//
//	Password restrictions:
//
//	- 8 characters minimum and 16 characters maximum
//	- Must contain characters at least from any 3 of 4 groups mentioned in the section "Characters allowed"
//
//	Parameters:
//	- szwPassword	(string)	The password to check.
//
//	Exceptions:
//	- KLSTD::STDE_NOFUNC	the password does not comply with the password policy
func (dp *DataProtectionApi) CheckPasswordSplPpc(ctx context.Context, szwPassword string) (*PxgValBool, []byte, error) {
	postData := []byte(fmt.Sprintf(`{"szwPassword": "%s"}`, szwPassword))
	request, err := http.NewRequest("POST", dp.client.Server+"/api/v1.0/DataProtectionApi.CheckPasswordSplPpc", bytes.NewBuffer(postData))
	if err != nil {
		return nil, nil, err
	}

	pxgValBool := new(PxgValBool)
	raw, err := dp.client.Do(ctx, request, &pxgValBool)
	return pxgValBool, raw, err
}

//	Protects sensitive data to store in SettingsStorage or local task.
//
//	Parameters:
//	- szwHostId	[in] host name
//	- pData	[in] pointer to data
//
//	- pDataProtected	[out] pointer to protected data block.
//
//Exceptions:
//	- KLSTD::STDE_NOTPERM	host has no public key (
//	possibly it doesn't support data protection or nagent isn't installed
//	there or host belongs to other virtual server)
//	- KLSTD::STDE_NOFUNC	server doesn't support data protection
//TODO func (dp *DataProtectionApi) ProtectDataForHost(ctx context.Context, szwHostId string, pData []byte) ([]byte,
//error)

//	Protects sensitive data to store in policy or global/group task.
//
//	Parameters:
//	- pData	[in] pointer to data
//	- pDataProtected	[out] pointer to protected data block.
//TODO func (dp *DataProtectionApi) ProtectDataForHost(ctx context.Context, szwHostId string, pData []byte) ([]byte,
//error)

//	Protects sensitive data for the specified host (to store in its local settings or a local task)
//
//	Protects the specified text as UTF16 string encrypted with the key of the specified host.
//
//	Parameters:
//	- szwHostId	[in] host name
//	- szwPlainText	[in] plainText
//
//	Returns:
//	- Ciphertext
func (dp *DataProtectionApi) ProtectUtf16StringForHost(ctx context.Context, szwHostId, szwPlainText string) ([]byte,
	error) {
	postData := []byte(fmt.Sprintf(`{"szwPassword" : "%s", "szwPlainText" : "%s"}`, szwHostId, szwPlainText))
	request, err := http.NewRequest("POST", dp.client.Server+"/api/v1.0/DataProtectionApi.ProtectUtf16StringForHost", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := dp.client.Do(ctx, request, nil)
	return raw, err
}

//	Protects sensitive data to store in policy, global/group task,
//	Administration Server settings.
//
//	Protects the specified text as UTF16 string encrypted with the key
//	of the Administration Server.
//
//	The same as Tasks::ProtectPassword
//
//	Parameters:
//	- szwPlainText	[in] plainText
//
//Returns:
//	- Ciphertext
func (dp *DataProtectionApi) ProtectUtf16StringGlobally(ctx context.Context, szwPlainText string) ([]byte,
	error) {
	postData := []byte(fmt.Sprintf(`{"szwPlainText" : "%s"}`, szwPlainText))
	request, err := http.NewRequest("POST", dp.client.Server+"/api/v1.0/DataProtectionApi.ProtectUtf16StringGlobally", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := dp.client.Do(ctx, request, nil)
	return raw, err
}

//	Protects sensitive data for the specified host
//	(to store in its local settings or a local task)
//
//	Protects the specified text as UTF8 string encrypted with the key
//	of the specified host.
//
//	Parameters:
//	- szwHostId	[in] host name
//	- szwPlainText	[in] plainText
//
//Returns:
//	- Ciphertext
func (dp *DataProtectionApi) ProtectUtf8StringForHost(ctx context.Context, szwHostId, szwPlainText string) ([]byte,
	error) {
	postData := []byte(fmt.Sprintf(`{"szwPassword" : "%s", "szwPlainText" : "%s"}`, szwHostId, szwPlainText))
	request, err := http.NewRequest("POST", dp.client.Server+"/api/v1.0/DataProtectionApi.ProtectUtf8StringForHost", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := dp.client.Do(ctx, request, nil)
	return raw, err
}

//	Protects sensitive data to store in policy, global/group task,
//	Administration Server settings.
//
//	Protects the specified text as UTF8 string encrypted with the key
//	of the Administration Server.
//
//	Parameters:
//	- szwPlainText	[in] plainText
//
//	Returns:
//	- Ciphertext
func (dp *DataProtectionApi) ProtectUtf8StringGlobally(ctx context.Context, szwPlainText string) ([]byte,
	error) {
	postData := []byte(fmt.Sprintf(`{"szwPlainText" : "%s"}`, szwPlainText))
	request, err := http.NewRequest("POST", dp.client.Server+"/api/v1.0/DataProtectionApi.ProtectUtf8StringGlobally", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := dp.client.Do(ctx, request, nil)
	return raw, err
}
