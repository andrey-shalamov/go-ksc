/*
 * MIT License
 *
 * Copyright (c) [2020] [Semchenko Aleksandr]
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package kaspersky

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

//	SubnetMasks Class Reference
//	Subnets provider.
//
//	List of all members.
type SubnetMasks service

//PSubnetSettings struct
type PSubnetSettings struct {
	//	PSubnetSettingsClass - Subnet parameters
	PSubnetSettingsClass *PSubnetSettingsClass `json:"pSubnetSettings,omitempty"`
}

type PSubnetSettingsClass struct {
	// NIPAddress - Subnet IP
	NIPAddress *int64 `json:"nIpAddress,omitempty"`
	// NMask - Subnet mask
	NMask *int64 `json:"nMask,omitempty"`
	//	WstrSubnetName - Subnet name (not empty, maximum 100 unicode symbols)
	WstrSubnetName *string `json:"wstrSubnetName,omitempty"`
	//	WstrComment - Subnet description
	WstrComment *string `json:"wstrComment,omitempty"`
}

//PSubnetSettings struct - Subnet parameters
type PSubnetUpdateSettings struct {
	// NIPAddress - Subnet IP
	NIPAddress *int64 `json:"nIpAddress,omitempty"`
	// NMask - Subnet mask
	NMask *int64 `json:"nMask,omitempty"`
	//	PSubnetSettings - new subnet parameters (params).
	//	If parameters not exist - it will be ignored
	PSubnetUpdateSettingsClass *PSubnetUpdateSettingsClass `json:"pSubnetSettings,omitempty"`
}

type PSubnetUpdateSettingsClass struct {
	//	WstrSubnetName - Subnet name (not empty, maximum 100 unicode symbols)
	WstrSubnetName *string `json:"wstrSubnetName,omitempty"`
	//	WstrComment - Subnet description
	WstrComment *string `json:"wstrComment,omitempty"`
}

//	Create subnet for current server with specific parameters
//
//	Parameters:
//	- pSubnetSettings	Subnet parameters (paramParams).
//	|- "nIpAddress" (int64) - Subnet IP
//	|- "nMask" (int64) - Subnet mask
//	|- "wstrSubnetName" (string) - Subnet name (not empty, maximum 100 unicode symbols)
//	|- "wstrComment" (string, optional) - Subnet description
//
//	Returns:
//	- Real subnet name: if subnet with specified name already exist - new subnet renamed with repaired suffix name
//
//	Exceptions:
//	- Throw	exception if subnet (ip-mask pair) already exists or if subnet (ip-mask pair) not correct
func (sm *SubnetMasks) CreateSubnet(ctx context.Context, params PSubnetSettings) ([]byte, error) {
	postData, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("POST", sm.client.Server+"/api/v1.0/SubnetMasks.CreateSubnet", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := sm.client.Do(ctx, request, nil)
	return raw, err
}

//	Remove existing subnet
//
//	Parameters:
//	- nIpAddress	(unsignedLong) Current server subnet IP
//	- nMask	(unsignedLong) Current server subnet mask
func (sm *SubnetMasks) DeleteSubnet(ctx context.Context, nIpAddress, nMask int64) ([]byte, error) {
	postData := []byte(fmt.Sprintf(`{"nIpAddress" : %d, "nMask" : %d}`, nIpAddress, nMask))

	request, err := http.NewRequest("POST", sm.client.Server+"/api/v1.0/SubnetMasks.DeleteSubnet", bytes.NewBuffer(postData))
	if err != nil {
		log.Fatal(err.Error())
	}

	raw, err := sm.client.Do(ctx, request, nil)
	return raw, err
}

//	Modify existing subnet parameters
//
//	Parameters:
//	- nIpAddress	(unsignedLong) Current server subnet IP
//	- nMask	(unsignedLong) Current server subnet mask
//		- pSubnetSettings	new subnet parameters (paramParams). If parameters not exist - it will be ignored
//		|- "wstrSubnetName" (paramString, optional) - Subnet name (not empty, maximum 100 unicode symbols)
//		|- "wstrComment" (paramString, optional) - Subnet description
//
//	Returns:
//	Real subnet name:
//	if subnet with specified changeable name already exist - subnet renamed with repaired suffix name
func (sm *SubnetMasks) ModifySubnet(ctx context.Context, params PSubnetUpdateSettings) ([]byte, error) {
	postData, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("POST", sm.client.Server+"/api/v1.0/SubnetMasks.ModifySubnet", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := sm.client.Do(ctx, request, nil)
	return raw, err
}
