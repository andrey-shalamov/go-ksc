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

	"net/http"
)

// NagHstCtl Manage nagent on host.
//
// This interface is implemented at Network Agent side, so use gateway connection to connect Network Agent and call interface methods.
type NagHstCtl service

// GetHostRuntimeInfo Acquire runtime host information
func (nh *NagHstCtl) GetHostRuntimeInfo(ctx context.Context, params interface{}) ([]byte, error) {
	postData, _ := json.Marshal(params)
	request, err := http.NewRequest("POST", nh.client.Server+"/api/v1.0/NagHstCtl.GetHostRuntimeInfo", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := nh.client.Do(ctx, request, nil)
	return raw, err
}

// SendTaskAction Initiate changing state of tasks at host
// The method sends to the specified product task one of such commands as 'start', 'stop', 'suspend', 'resume'.
func (nh *NagHstCtl) SendTaskAction(ctx context.Context, szwProduct, szwVersion, szwTaskStorageId string,
	nTaskAction int64) ([]byte, error) {
	postData := []byte(fmt.Sprintf(`{"szwProduct": "%s", "szwVersion": "%s", "szwTaskStorageId": "%s", "nTaskAction": %d }`,
		szwProduct, szwVersion, szwTaskStorageId, nTaskAction))
	request, err := http.NewRequest("POST", nh.client.Server+"/api/v1.0/NagHstCtl.SendTaskAction", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := nh.client.Do(ctx, request, nil)
	return raw, err
}

// SendProductAction Initiate changing state of products at host
// The method sends to the specified product 'start' or 'stop' command.
func (nh *NagHstCtl) SendProductAction(ctx context.Context, szwProduct, szwVersion string, nProductAction int64) ([]byte, error) {
	postData := []byte(fmt.Sprintf(` { "szwProduct": "%s", "szwVersion": "%s", "nProductAction": %d }`, szwProduct, szwVersion, nProductAction))
	request, err := http.NewRequest("POST", nh.client.Server+"/api/v1.0/NagHstCtl.SendProductAction", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := nh.client.Do(ctx, request, nil)
	return raw, err
}
