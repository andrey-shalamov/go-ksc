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
	"encoding/json"
	"fmt"

	"net/http"
)

//	SrvView Class Reference
//	Interface to get plain-queries from SC-server.
//	List of all members.
type SrvView service

//SrvViewParams struct
type SrvViewParams struct {
	WstrViewName      *string         `json:"wstrViewName"`
	WstrFilter        *string         `json:"wstrFilter"`
	VecFieldsToReturn []string        `json:"vecFieldsToReturn"`
	VecFieldsToOrder  []FieldsToOrder `json:"vecFieldsToOrder"`
	PParams           *ESrvViewParams `json:"pParams"`
	LifetimeSEC       *int64          `json:"lifetimeSec"`
}

type ESrvViewParams struct {
	TopN *int64 `json:"TOP_N,omitempty"`
}

//	Find srvview data by filter string.
//
//	Finds data records for srvview wstrViewName that satisfy conditions from filter string wstrFilter,
//	and creates a server-side collection of found data records.
//
//	Parameters:
//	Example:
//	{
//		"wstrViewName":"HWInvStorageSrvViewName",
//		"wstrFilter":"(&(MotherBoard=\"*\"))",
//		"vecFieldsToReturn":["Id","Type","CPU"],
//		"vecFieldsToOrder":null,
//		"pParams":null,
//		"lifetimeSec":7200
//	}
//	- wstrViewName	(string) name of srvview see List of supported srvviews.
//	- wstrFilter	(string) filter string, contains a condition over srvview attributes, see also Search filter syntax.
//	- vecFieldsToReturn	(array) array of srvview attribute names to return.
//	- vecFieldsToOrder	(array) array of containers each of them containing two attributes:
//	- "Name" (string) name of attribute used for sorting
//	- "Asc" (bool) ascending if true descending otherwise
//	- pParams	(params) extra options. This parameter can contain additional options to configure query.
//	Some options are specific to the wstrViewName and are part of it specification.
//	And some options are common for all srvviews. List of common options:
//	- "TOP_N" (int64) acquire only first N records
//	- lifetimeSec	(int64) max result-set lifetime in seconds
// 	- [out]	wstrIteratorId	(string) result-set ID, identifier of the server-side ordered collection of found data records.
//	The result-set is destroyed and associated memory is freed in following cases:
//	Passed lifetimeSec seconds after last access to the result-set (by methods GetRecordCount and GetRecordRange).
//	Session to the Administration Server has been closed.
//	ReleaseIterator has been called.
func (sv *SrvView) ResetIterator(ctx context.Context, params SrvViewParams) (*WstrIteratorID, []byte, error) {
	postData, err := json.Marshal(params)
	if err != nil {
		return nil, nil, err
	}

	request, err := http.NewRequest("POST", sv.client.Server+"/api/v1.0/SrvView.ResetIterator", bytes.NewBuffer(postData))
	if err != nil {
		return nil, nil, err
	}

	srvViewIter := new(WstrIteratorID)
	raw, err := sv.client.Do(ctx, request, &srvViewIter)
	return srvViewIter, raw, err
}

//	Acquire count of result-set elements.
//
//	Returns number of elements contained in the specified result-set.
//
//	Parameters:
//	- wstrIteratorId	(string) result-set ID, identifier of the server-side ordered collection of found data records
//
//	Returns:
//	(int64) number of elements contained in the specified result-set
func (sv *SrvView) GetRecordCount(ctx context.Context, wstrIteratorId string) (*PxgValInt, []byte, error) {
	postData := []byte(fmt.Sprintf(`{"wstrIteratorId":"%s"}`, wstrIteratorId))
	request, err := http.NewRequest("POST", sv.client.Server+"/api/v1.0/SrvView.GetRecordCount", bytes.NewBuffer(postData))
	if err != nil {
		return nil, nil, err
	}

	pxgValInt := new(PxgValInt)
	raw, err := sv.client.Do(ctx, request, &pxgValInt)
	return pxgValInt, raw, err
}

//	Release result-set.
//
//	Releases the specified result-set and frees associated memory
//
//	Parameters:
//
//	wstrIteratorId	(string) result-set ID, identifier of the server-side ordered collection of found data records
func (sv *SrvView) ReleaseIterator(ctx context.Context, wstrIteratorId string) ([]byte, error) {
	postData := []byte(fmt.Sprintf(`{"wstrIteratorId":"%s"}`, wstrIteratorId))
	request, err := http.NewRequest("POST", sv.client.Server+"/api/v1.0/SrvView.ReleaseIterator", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := sv.client.Do(ctx, request, nil)
	return raw, err
}

type RecordRangeParams struct {
	WstrIteratorID *string `json:"wstrIteratorId,omitempty"`
	NStart         *int64  `json:"nStart,omitempty"`
	NEnd           *int64  `json:"nEnd,omitempty"`
}

//	Acquire subset of result-set elements by range.
//
//	Returns elements contained in the specified result-set in the diapason
//	from position nStart to position nEnd.
//
//	Parameters:
//	- wstrIteratorId	(string) result-set ID, identifier of the server-side
//	ordered collection of found data records
//	- nStart	(int64) zero-based start position
//	- nEnd	(int64) zero-based finish position
//
//	Return:
//	- pRecords	(params) container that has needed elements in the array with name "KLCSP_ITERATOR_ARRAY"
func (sv *SrvView) GetRecordRange(ctx context.Context, params RecordRangeParams) ([]byte, error) {
	postData, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("POST", sv.client.Server+"/api/v1.0/SrvView.GetRecordRange", bytes.NewBuffer(postData))
	if err != nil {
		return nil, err
	}

	raw, err := sv.client.Do(ctx, request, nil)
	return raw, err
}
