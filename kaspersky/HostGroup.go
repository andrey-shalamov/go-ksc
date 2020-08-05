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
	"context"
	"fmt"
)

// HostGroup service allow to Hosts and management groups processing.
type HostGroup service

// AddDomain Add a new domain to the database.
func (hg *HostGroup) AddDomain(ctx context.Context, strDomain string, nType int64) ([]byte, error) {
	params := []byte(fmt.Sprintf(`{"strDomain": "%s", "nType" : %d }`, strDomain, nType))
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.AddDomain", params, nil)
}

// AddGroupParams struct
type AddGroupParams struct {
	PInfo *GroupPInfo `json:"pInfo,omitempty"`
}

type GroupPInfo struct {
	Name     *string `json:"name,omitempty"`
	ParentID *int64  `json:"parentId,omitempty"`
}

// AddGroup Creates new group with the specified attributes and returns its Id.
// If such group already exists returns Id of existing group.
func (hg *HostGroup) AddGroup(ctx context.Context, params AddGroupParams) (*PxgValInt, []byte, error) {
	pxgValInt := new(PxgValInt)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.AddGroup", params, pxgValInt)
	return pxgValInt, raw, err
}

// AddGroupHostsForSync Add hosts from specified group to synchronization.
func (hg *HostGroup) AddGroupHostsForSync(ctx context.Context, nGroupId int64, strSSType string) (*WActionGUID, []byte, error) {
	params := []byte(fmt.Sprintf(` {"nGroupId": %d , "strSSType": "%s" }`, nGroupId, strSSType))
	wActionGUID := new(WActionGUID)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.AddGroupHostsForSync", params, wActionGUID)
	return wActionGUID, raw, err
}

// AddHost Create new host record.
func (hg *HostGroup) AddHost(ctx context.Context, params interface{}) (*PxgValStr, []byte, error) {
	pxgValStr := new(PxgValStr)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.AddHost", params, pxgValStr)
	return pxgValStr, raw, err
}

// HostsForSyncParams struct using in HostGroup.AddHostsForSync
type HostsForSyncParams struct {
	// PHostNames array of host names
	PHostNames []string `json:"pHostNames"`

	// StrSSType setting storage identity (empty string means synchronization of all setting storages)
	StrSSType string `json:"strSSType,omitempty"`
}

// AddHostsForSync Performs synchronization of settings between server and host.
func (hg *HostGroup) AddHostsForSync(ctx context.Context, params HostsForSyncParams) (*WActionGUID, []byte, error) {
	wActionGUID := new(WActionGUID)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.AddHostsForSync", params, wActionGUID)
	return wActionGUID, raw, err
}

// AddIncidentsParams struct
type AddIncidentsParams struct {
	PData PData `json:"pData"`
}

// PData struct
type PData struct {
	KlincdtSeverity  int64     `json:"KLINCDT_SEVERITY"`
	KlincdtAdded     *DateTime `json:"KLINCDT_ADDED"`
	KlincdtBody      string    `json:"KLINCDT_BODY"`
	KlhstWksHostname string    `json:"KLHST_WKS_HOSTNAME"`
	KlhstuserID      int64     `json:"KLHSTUSER_ID"`
}

// AddIncident Create new incident.
func (hg *HostGroup) AddIncident(ctx context.Context, params AddIncidentsParams) (*PxgValStr, []byte, error) {
	pxgValStr := new(PxgValStr)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.AddIncident", params, pxgValStr)
	return pxgValStr, raw, err
}

// DelDomain Removes a domain from the database.
func (hg *HostGroup) DelDomain(ctx context.Context, strDomain string) ([]byte, error) {
	params := []byte(fmt.Sprintf(`{ "strDomain": "%s" }`, strDomain))
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.DelDomain", params, nil)
}

// DeleteIncident Delete incident.
func (hg *HostGroup) DeleteIncident(ctx context.Context, nId int64) ([]byte, error) {
	params := []byte(fmt.Sprintf(`{"nId": %d}`, nId))
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.DeleteIncident", params, nil)
}

// HGParams struct
type HGParams struct {
	WstrFilter        string          `json:"wstrFilter"`
	VecFieldsToReturn []string        `json:"vecFieldsToReturn"`
	VecFieldsToOrder  []FieldsToOrder `json:"vecFieldsToOrder"`
	PParams           PParams         `json:"pParams"`
	LMaxLifeTime      int64           `json:"lMaxLifeTime"`
}

type PParams struct {
	KlsrvhSlaveRecDepth    int64 `json:"KLSRVH_SLAVE_REC_DEPTH"`
	KlgrpFindFromCurVsOnly bool  `json:"KLGRP_FIND_FROM_CUR_VS_ONLY"`
}

// FindGroups Finds groups that satisfy conditions from filter pParams, and creates a server-side collection of found groups.
// Search is performed over the hierarchy
func (hg *HostGroup) FindGroups(ctx context.Context, params HGParams) (*Accessor, []byte, error) {
	accessor := new(Accessor)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.FindGroups", params, accessor)
	return accessor, raw, err
}

// FindHosts Finds hosts that satisfy conditions from filter string wstrFilter, and creates a server-side collection of found hosts.
// Search is performed over the hierarchy
func (hg *HostGroup) FindHosts(ctx context.Context, params HGParams) (*Accessor, []byte, error) {
	accessor := new(Accessor)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.FindHosts", params, accessor)
	return accessor, raw, err
}

// FindHostsAsync Find host asynchronously by filter string.
// Finds hosts asynchronously that satisfy conditions from filter string wstrFilter,
// and creates a server-side collection of found hosts. Search is performed over the hierarchy
// to get status use AsyncActionStateChecker.CheckActionState, lStateCode "1" means OK and "0" means fail
// to get accessor id call HostGroup.FindHostsAsyncGetAccessor
// to cancel operation call HostGroup.FindHostsAsyncCancel
func (hg *HostGroup) FindHostsAsync(ctx context.Context, params HGParams) (*RequestID, []byte, error) {
	requestID := new(RequestID)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.FindHostsAsync", params, requestID)
	return requestID, raw, err
}

// FindHostsAsyncCancel Cancels asynchronous operation HostGroup.FindHostsAsync
func (hg *HostGroup) FindHostsAsyncCancel(ctx context.Context, strRequestId string) ([]byte, error) {
	params := []byte(fmt.Sprintf(`{ "strRequestId": "%s" }`, strRequestId))
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.FindHostsAsyncCancel", params, nil)
}

// FindHostsAsyncGetAccessor Gets result of asynchronous operation HostGroup.FindHostsAsync
func (hg *HostGroup) FindHostsAsyncGetAccessor(ctx context.Context, strRequestId string) (*AsyncAccessor, []byte,
	error) {
	params := []byte(fmt.Sprintf(`{"strRequestId" : "%s" }`, strRequestId))
	asyncAccessor := new(AsyncAccessor)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.FindHostsAsyncGetAccessor", params, asyncAccessor)
	return asyncAccessor, raw, err
}

// FindIncidentsParams struct
type FindIncidentsParams struct {
	StrFilter       string          `json:"strFilter,omitempty"`
	PFieldsToReturn []string        `json:"pFieldsToReturn,omitempty"`
	PFieldsToOrder  []FieldsToOrder `json:"pFieldsToOrder,omitempty"`
	LMaxLifeTime    int64           `json:"lMaxLifeTime,omitempty"`
}

// FindIncidents Find incident by filter string. Finds incidents that satisfy conditions from filter string strFilter.
func (hg *HostGroup) FindIncidents(ctx context.Context, params FindIncidentsParams) (*Accessor, []byte, error) {
	accessor := new(Accessor)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.FindIncidents", params, accessor)
	return accessor, raw, err
}

// FindUsers Finds existing users. Finds users that satisfy conditions from filter string strFilter.
func (hg *HostGroup) FindUsers(ctx context.Context, params PFindParams) (*Accessor, []byte, error) {
	accessor := new(Accessor)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.FindUsers", params, accessor)
	return accessor, raw, err
}

// GetAllHostfixes Returns all hotfixes installed in the network.
func (hg *HostGroup) GetAllHostfixes(ctx context.Context) ([]byte, error) {
	return hg.client.PostOut(ctx, "/api/v1.0/HostGroup.GetAllHostfixes", nil)
}

//	ProductComponents is returned by GetComponentsForProductOnHost
type ProductComponents struct {
	ProductComponentsArray []ProductComponentsArray `json:"PxgRetVal"`
}

type ProductComponentsArray struct {
	Type             string            `json:"type,omitempty"`
	ProductComponent *ProductComponent `json:"value,omitempty"`
}

type ProductComponent struct {
	KlhstPrcstComponentDN      string                      `json:"KLHST_PRCST_COMPONENT_DN,omitempty"`
	KlhstPrcstComponentID      *KlhstPrcstComponentID      `json:"KLHST_PRCST_COMPONENT_ID,omitempty"`
	KlhstPrcstComponentStatus  int64                       `json:"KLHST_PRCST_COMPONENT_STATUS,omitempty"`
	KlhstPrcstComponentVersion *KlhstPrcstComponentVersion `json:"KLHST_PRCST_COMPONENT_VERSION,omitempty"`
}

type KlhstPrcstComponentID struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

type KlhstPrcstComponentVersion struct {
	Type  string `json:"type,omitempty"`
	Value int64  `json:"value,omitempty"`
}

// GetComponentsForProductOnHost Return array of product components for specified host and product.
func (hg *HostGroup) GetComponentsForProductOnHost(ctx context.Context, strHostName, strProductName,
	strProductVersion string) (*ProductComponents, []byte, error) {
	params := []byte(fmt.Sprintf(`{"strHostName": "%s","strProductName": "%s","strProductVersion": "%s"}`,
		strHostName, strProductName, strProductVersion))
	productComponents := new(ProductComponents)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetComponentsForProductOnHost", params, productComponents)
	return productComponents, raw, err
}

// GetDomainHosts Return a list of workstation names in the domain.
//
// The information is obtained from the domain controller.
// This call returns the full list of workstations in the domain, even if the workstation is now turned off.
//
// Deprecated: use either HostGroup.FindHostsAsync or HostGroup.FindHosts instead.
func (hg *HostGroup) GetDomainHosts(ctx context.Context, domain string) ([]byte, error) {
	params := []byte(fmt.Sprintf(`{"domain": "%s"}`, domain))
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetDomainHosts", params, nil)
}

// WindowsDomainType - domain type:
type WindowsDomainType int

// 0 - Windows NT domain
// 1 - Windows work group
const (
	WindowsNTDomain WindowsDomainType = iota
	WindowsWorkGroup
)

// Domain - Windows domain info
type Domain struct {
	Name string            `json:"KLHST_WKS_WINDOMAIN,omitempty"`
	Type WindowsDomainType `json:"KLHST_WKS_WINDOMAIN_TYPE,omitempty"`
}

// DomainParams - Windows domain info
type DomainParams struct {
	Domain `json:"value,omitempty"`
}

type domains struct {
	Domains []DomainParams `json:"PxgRetVal,omitempty"`
}

// GetDomains List of Windows domain in the network.
func (hg *HostGroup) GetDomains(ctx context.Context) ([]DomainParams, []byte, error) {
	out := new(domains)
	raw, err := hg.client.PostOut(ctx, "/api/v1.0/HostGroup.GetDomains", &out)
	return out.Domains, raw, err
}

// GetGroupId Acquire administration group id by its name and id of parent group.
func (hg *HostGroup) GetGroupId(ctx context.Context, nParent int64, strName string) (*PxgValInt, []byte, error) {
	params := []byte(fmt.Sprintf(`{"nParent": %d, "strName": "%s"}`, nParent, strName))
	pxgValInt := new(PxgValInt)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetGroupId", params, pxgValInt)
	return pxgValInt, raw, err
}

// GetGroupInfo Acquire administration group attributes.
//
// Deprecated: Use HostGroup.GetGroupInfoEx instead
func (hg *HostGroup) GetGroupInfo(ctx context.Context, nGroupId int64) ([]byte, error) {
	params := []byte(fmt.Sprintf(`{"nGroupId": %d}`, nGroupId))
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetGroupInfo", params, nil)
}

// GetGroupInfoEx Acquire administration group attributes.
//
// Remark: not working on KSC 10
func (hg *HostGroup) GetGroupInfoEx(ctx context.Context, params interface{}) ([]byte, error) {
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetGroupInfoEx", params, nil)
}

// ProductFixes struct
type ProductFixes struct {
	Fixes []Fixes `json:"PxgRetVal"`
}

type Fixes struct {
	Type       string     `json:"type"`
	FixesValue FixesValue `json:"value"`
}

type FixesValue struct {
	KlhstHFDN string `json:"KLHST_HF_DN"`
	KlhstHFID string `json:"KLHST_HF_ID"`
}

// GetHostfixesForProductOnHost Return array of hotfixes for specified host and product.
// Array is ordered according hotfix installation order.
func (hg *HostGroup) GetHostfixesForProductOnHost(ctx context.Context, strHostName, strProductName, strProductVersion string) (*ProductFixes, []byte, error) {
	postData := []byte(fmt.Sprintf(`{"strHostName": "%s","strProductName": "%s","strProductVersion": "%s"}`, strHostName, strProductName, strProductVersion))
	productFixes := new(ProductFixes)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetHostfixesForProductOnHost", postData, productFixes)
	return productFixes, raw, err
}

// GetHostInfo Acquire specified host attributes.
func (hg *HostGroup) GetHostInfo(ctx context.Context, params interface{}) ([]byte, error) {
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetHostInfo", params, nil)
}

//DateTimeParams - KSC paramDateTime.
type DateTimeParams struct {
	Value string `json:"value"`
}

// HostProductInfo - host's product info
type HostProductInfo struct {
	BaseRecords       int
	BaseGeneration    int
	ModuleType        int
	Name              string
	Version           string
	DisplayName       string
	ProdVersion       string
	DataFolder        string
	Folder            string
	KeyFolder         string
	FileName          string
	FilePath          string
	CustomName        string
	LocID             string
	OsName            string
	OsVersion         string
	OsRelease         string
	InstallationId    string
	InstallTime       DateTimeParams
	LastUpdateTime    DateTimeParams
	BaseDate          DateTimeParams
	AcceptedCmds      []string
	Tasks             []string
	TasksComplemented []string
	Events            []string
}

// HostProductInfo - host's product info
type hostProductInfoParams struct {
	HostProductInfo `json:"value"`
}

// HostProductVersionParams -
type hostProductVersionParams struct {
	Value map[string]hostProductInfoParams `json:"value"`
}

// GetHostProductsResponse -
type getHostProductsResponse struct {
	PxgRetVal map[string]hostProductVersionParams `json:"PxgRetVal"`
}

// GetHostProducts Return information about installed products on the host.
func (hg *HostGroup) GetHostProducts(ctx context.Context, hostName string) ([]HostProductInfo, []byte, error) {
	in := []byte(fmt.Sprintf(`{"strHostName": "%s"}`, hostName))
	var out getHostProductsResponse
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetHostProducts", in, &out)
	var products []HostProductInfo
	for name, v1 := range out.PxgRetVal {
		for version, v2 := range v1.Value {
			v2.HostProductInfo.Name = name
			v2.HostProductInfo.Version = version
			products = append(products, v2.HostProductInfo)
		}
	}
	return products, raw, err
}

// GetHostTasks Return server specific identity to acquire and manage host tasks.
func (hg *HostGroup) GetHostTasks(ctx context.Context, hostId string) (*PxgValStr, []byte, error) {
	postData := []byte(fmt.Sprintf(`{"strHostName": "%s"}`, hostId))
	pxgValStr := new(PxgValStr)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetHostTasks", postData, pxgValStr)
	return pxgValStr, raw, err
}

// InstanceStatisticsParams struct
type InstanceStatisticsParams struct {
	// VecFilterFields Array of needed attributes
	// Remark: can be empty, but not nil
	VecFilterFields []string `json:"vecFilterFields"`
}

// GetInstanceStatistics Acquire Server statistics info.
//
// Remark: not working on KSC 10
func (hg *HostGroup) GetInstanceStatistics(ctx context.Context, params InstanceStatisticsParams) ([]byte, error) {
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetInstanceStatistics", params, nil)
}

// StaticInfoParams struct
type StaticInfoParams struct {
	PValues []string `json:"pValues"`
}

// GetRunTimeInfo Return server run-time info.
func (hg *HostGroup) GetRunTimeInfo(ctx context.Context, params StaticInfoParams) ([]byte, error) {
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetRunTimeInfo", params, nil)
}

// GetStaticInfo Return server static info.
func (hg *HostGroup) GetStaticInfo(ctx context.Context, params StaticInfoParams) ([]byte, error) {
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetStaticInfo", params, nil)
}

// GetSubgroups Acquire administration group subgroups tree.
func (hg *HostGroup) GetSubgroups(ctx context.Context, nGroupId int64, nDepth int64) ([]byte, error) {
	postData := []byte(fmt.Sprintf(`{"nParent": %d, "nDepth": %d }`, nGroupId, nDepth))
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.GetSubgroups", postData, nil)
}

// GroupIdGroups Id of predefined root group "Managed computers".
func (hg *HostGroup) GroupIdGroups(ctx context.Context) (*PxgValInt, []byte, error) {
	pxgValInt := new(PxgValInt)
	raw, err := hg.client.PostOut(ctx, "/api/v1.0/HostGroup.GroupIdGroups", pxgValInt)
	return pxgValInt, raw, err
}

// GroupIdSuper Id of predefined group "Master server".
func (hg *HostGroup) GroupIdSuper(ctx context.Context) (*PxgValInt, []byte, error) {
	pxgValInt := new(PxgValInt)
	raw, err := hg.client.PostOut(ctx, "/api/v1.0/HostGroup.GroupIdSuper", pxgValInt)
	return pxgValInt, raw, err
}

// GroupIdUnassigned Id of predefined group "Unassigned computers".
func (hg *HostGroup) GroupIdUnassigned(ctx context.Context) (*PxgValInt, []byte, error) {
	pxgValInt := new(PxgValInt)
	raw, err := hg.client.PostOut(ctx, "/api/v1.0/HostGroup.GroupIdUnassigned", pxgValInt)
	return pxgValInt, raw, err
}

// MoveHostsFromGroupToGroup Moves hosts from root of source group to root of destination group. Operation is asynchronous.
func (hg *HostGroup) MoveHostsFromGroupToGroup(ctx context.Context, nSrcGroupId int64,
	nDstGroupId int64) (*WActionGUID, []byte, error) {
	postData := []byte(fmt.Sprintf(`{"nSrcGroupId": %d, "nDstGroupId": %d}`, nSrcGroupId, nDstGroupId))
	wActionGUID := new(WActionGUID)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.MoveHostsFromGroupToGroup", postData, wActionGUID)
	return wActionGUID, raw, err
}

// HostsToGroupParams struct
type HostsToGroupParams struct {
	NGroup     int64    `json:"nGroup"`
	PHostNames []string `json:"pHostNames"`
}

// MoveHostsToGroup Move multiple hosts into specified administration group.
func (hg *HostGroup) MoveHostsToGroup(ctx context.Context, params HostsToGroupParams) ([]byte, error) {
	return hg.client.PostIn(ctx, "/api/v1.0/HostGroup.MoveHostsToGroup", params)
}

// RemoveGroup Delete administration group.
func (hg *HostGroup) RemoveGroup(ctx context.Context, nGroup, nFlags int64) (*WActionGUID, []byte, error) {
	in := []byte(fmt.Sprintf(`{ "nGroup": %d, "nFlags": %d }`, nGroup, nFlags))
	wActionGUID := new(WActionGUID)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.RemoveGroup", in, wActionGUID)
	return wActionGUID, raw, err
}

// RemoveHost Removes host record.
func (hg *HostGroup) RemoveHost(ctx context.Context, strHostName string) ([]byte, error) {
	in := []byte(fmt.Sprintf(`{ "strHostName": "%s" }`, strHostName))
	return hg.client.PostIn(ctx, "/api/v1.0/HostGroup.RemoveHost", in)
}

// RemoveHostsParams struct
type RemoveHostsParams struct {
	//Array of host names
	PHostNames []string `json:"pHostNames"`
	//Whether to force deleting hosts records
	BForceDestroy bool `json:"bForceDestroy"`
}

// RemoveHosts Remove multiple hosts.
//
// Removes multiple hosts. Function behavior depends on bForceDestroy flag.
//
//If bForceDestroy is true then hosts records are deleted.
//
//If bForceDestroy is false hosts records will be deleted only for hosts located in group "Unassigned computers"
// or its subgroups, others will be moved into corresponding subgroups of group "Unassigned computers".
func (hg *HostGroup) RemoveHosts(ctx context.Context, params RemoveHostsParams) ([]byte, error) {
	return hg.client.PostIn(ctx, "/api/v1.0/HostGroup.RemoveHosts", params)
}

// KlhstWksResults struct
type KlhstWksResults struct {
	PResults PResults `json:"pResults"`
}

type PResults struct {
	KlhstWksResults []bool `json:"KLHST_WKS_RESULTS"`
}

// PInfoRaM struct
type PInfoRaM struct {
	PInfo PInfo `json:"pInfo"`
}

type PInfo struct {
	KlhstWksAnyname []string `json:"KLHST_WKS_ANYNAME"`
	KlhstWksGroupid int64    `json:"KLHST_WKS_GROUPID"`
}

// ResolveAndMoveToGroup Moves hosts into a group by name or ip-address.
//
// If the entered name corresponds to the ip-address format, then the server tries to find in the database a host with the indicated ip-address.
// Otherwise, the server tries to interpret the host as follows:
//
// 1. Name (KLHST_WKS_HOSTNAME)
//
//2. Display name (KLHST_WKS_DN)
//
//3. NetBIOS name (KLHST_WKS_WINHOSTNAME)
//
//4. DNS name (KLHST_WKS_DNSNAME)
func (hg *HostGroup) ResolveAndMoveToGroup(ctx context.Context, params PInfoRaM) (*KlhstWksResults, []byte, error) {
	klhstWksResults := new(KlhstWksResults)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.ResolveAndMoveToGroup", params, klhstWksResults)
	return klhstWksResults, raw, err
}

// RestartNetworkScanning Restarts specified network scanning type.
func (hg *HostGroup) RestartNetworkScanning(ctx context.Context, nType int64) (*PxgRetError, []byte, error) {
	postData := []byte(fmt.Sprintf(`{"nType": %d	}`, nType))
	pxgRetError := new(PxgRetError)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.RestartNetworkScanning", postData, pxgRetError)
	return pxgRetError, raw, err
}

// SetLocInfo Allows to set server localization information.
func (hg *HostGroup) SetLocInfo(ctx context.Context, params interface{}) ([]byte, error) {
	return hg.client.PostIn(ctx, "/api/v1.0/HostGroup.SetLocInfo", params)
}

//SectionParams struct using in HostGroup.SS_CreateSection | HostGroup.SS_DeleteSection
type SectionParams struct {
	//host name (unique server-generated string)
	StrHostName string `json:"strHostName,omitempty"`

	//type of storage (for example: "SS_SETTINGS")
	StrType string `json:"strType,omitempty"`

	//product name string, non-empty string, not longer than 31 character, and cannot contain characters /\:*?"<>.
	StrProduct string `json:"strProduct,omitempty"`

	//version string, non-empty string, not longer than 31 character, and cannot contain characters /\:*?"<>.
	StrVersion string `json:"strVersion,omitempty"`

	//section name string, non-empty string, not longer than 31 character, and cannot contain characters /\:*?"<>.
	StrSection string `json:"strSection,omitempty"`

	//write option, values:
	//	1 - "Update", updates existing variables in the specified section. If a variable does not exist an error occurs.
	//	2 - "Add", adds new variables to the specified section. If a variable already exists an error occurs.
	//	3 - "Replace", replaces variables in the specified section. If a variable already exists it will be updates, if a variable does not exist it will be added.
	//	4 - "Delete", deletes variables specified in pData from the specified section.
	//	7 - "Clear", replaces existing section contents with pData, i.e. existing section contents will deleted and variables from pData will be written to the section.
	NOption   int64       `json:"nOption,omitempty"`
	PSettings interface{} `json:"pSettings,omitempty"`
}

// SSCreateSection Create section in host settings storage.
func (hg *HostGroup) SSCreateSection(ctx context.Context, params SectionParams) ([]byte, error) {
	return hg.client.PostIn(ctx, "/api/v1.0/HostGroup.SS_CreateSection", params)
}

// SSWrite Write data to host settings storage.
func (hg *HostGroup) SSWrite(ctx context.Context, params SectionParams) ([]byte, error) {
	return hg.client.PostIn(ctx, "/api/v1.0/HostGroup.SS_Write", params)
}

// SSGetNames Get section names from host settings storage.
//
// If product is empty then names will contain all product names.
// If product is not empty and version is empty then names will contain all versions for the specified product name.
// If product is not empty and version is not empty then names will contain all sections for the specified product and version.
func (hg *HostGroup) SSGetNames(ctx context.Context, params SectionParams) (*PxgValArrayOfString, []byte, error) {
	pxgValArrayOfString := new(PxgValArrayOfString)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.SS_GetNames", params, pxgValArrayOfString)
	return pxgValArrayOfString, raw, err
}

// SSRead Read data from host settings storage.
func (hg *HostGroup) SSRead(ctx context.Context, params SectionParams) ([]byte, error) {
	return hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.SS_Read", params, nil)
}

// UpdateGroup Change attributes of existing administration group.
func (hg *HostGroup) UpdateGroup(ctx context.Context, params interface{}) (*PxgValStr, []byte, error) {
	pxgValStr := new(PxgValStr)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.UpdateGroup", params, pxgValStr)
	return pxgValStr, raw, err
}

// UpdateHost Modify specified attributes for host.
func (hg *HostGroup) UpdateHost(ctx context.Context, params interface{}) ([]byte, error) {
	return hg.client.PostIn(ctx, "/api/v1.0/HostGroup.UpdateHost", params)
}

// UpdateHostsMultiple Update attributes of multiple computers.
func (hg *HostGroup) UpdateHostsMultiple(ctx context.Context, params interface{}) ([]byte, error) {
	return hg.client.PostIn(ctx, "/api/v1.0/HostGroup.UpdateHostsMultiple", params)
}

// UpdateIncidentParams struct using in HostGroup.UpdateIncident
type UpdateIncidentParams struct {
	NID   int64          `json:"nId,omitempty"`
	PData *PIncidentData `json:"pData,omitempty"`
}

type PIncidentData struct {
	KlhstWksHostname string `json:"KLHST_WKS_HOSTNAME"`
	//Incident body
	KlincdtBody string `json:"KLINCDT_BODY,omitempty"`
	//Incident severity
	KlincdtSeverity int64 `json:"KLINCDT_SEVERITY,omitempty"`
	//Time of incident entry creation
	KlincdtAdded *DateTime `json:"KLINCDT_ADDED,omitempty"`
	//"IsHandled" flag. True - if incident marked as "Handled", otherwise false
	KlincdtIsHandled bool `json:"KLINCDT_IS_HANDLED,omitempty"`
}

// UpdateIncident Modify properties of an existing incident.
func (hg *HostGroup) UpdateIncident(ctx context.Context, params UpdateIncidentParams) ([]byte, error) {
	return hg.client.PostIn(ctx, "/api/v1.0/HostGroup.UpdateIncident", params)
}

// ZeroVirusCountForGroup Zero virus count for hosts in group and all subgroups.
func (hg *HostGroup) ZeroVirusCountForGroup(ctx context.Context, nParent int64) (*WActionGUID, []byte, error) {
	postData := []byte(fmt.Sprintf(`{"nParent": %d}`, nParent))
	wActionGUID := new(WActionGUID)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.ZeroVirusCountForGroup", postData, wActionGUID)
	return wActionGUID, raw, err
}

// ZeroVirusCountForHosts Zero virus count for specified hosts.
func (hg *HostGroup) ZeroVirusCountForHosts(ctx context.Context, params interface{}) (*WActionGUID, []byte, error) {
	wActionGUID := new(WActionGUID)
	raw, err := hg.client.PostInOut(ctx, "/api/v1.0/HostGroup.ZeroVirusCountForHosts", params, wActionGUID)
	return wActionGUID, raw, err
}
