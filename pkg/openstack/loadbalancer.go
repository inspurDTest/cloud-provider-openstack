/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package openstack

import (
	"context"
	"encoding/json"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/containers"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/secrets"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/loadbalancers"
	v2monitors "github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/monitors"
	v2pools "github.com/gophercloud/gophercloud/openstack/loadbalancer/v2/pools"
	neutrontags "github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/attributestags"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	neutronports "github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	secgroups "github.com/gophercloud/utils/openstack/networking/v2/extensions/security/groups"
	cloudprovider "github.com/inspurDTest/cloud-provider"
	"gopkg.in/godo.v2/glob"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
	"k8s.io/utils/strings/slices"

	"github.com/inspurDTest/cloud-provider-openstack/pkg/metrics"
	cpoutil "github.com/inspurDTest/cloud-provider-openstack/pkg/util"
	cpoerrors "github.com/inspurDTest/cloud-provider-openstack/pkg/util/errors"
	netsets "github.com/inspurDTest/cloud-provider-openstack/pkg/util/net/sets"
	openstackutil "github.com/inspurDTest/cloud-provider-openstack/pkg/util/openstack"
)

// Note: when creating a new Loadbalancer (VM), it can take some time before it is ready for use,
// this timeout is used for waiting until the Loadbalancer provisioning status goes to ACTIVE state.
const (
	servicePrefix                       = "k8s"
	serviceClusterId                    = "192549fb-ddd7-5449-a33d-d3f302a680f3"
	defaultLoadBalancerSourceRangesIPv4 = "0.0.0.0/0"
	defaultLoadBalancerSourceRangesIPv6 = "::/0"
	activeStatus                        = "ACTIVE"
	errorStatus                         = "ERROR"
	annotationXForwardedFor             = "X-Forwarded-For"

	ServiceAnnotationLoadBalancerInternal             = "service.beta.kubernetes.io/openstack-internal-load-balancer"
	ServiceAnnotationLoadBalancerConnLimit            = "loadbalancer.openstack.org/connection-limit"
	ServiceAnnotationLoadBalancerFloatingNetworkID    = "loadbalancer.openstack.org/floating-network-id"
	ServiceAnnotationLoadBalancerFloatingSubnet       = "loadbalancer.openstack.org/floating-subnet"
	ServiceAnnotationLoadBalancerFloatingSubnetID     = "loadbalancer.openstack.org/floating-subnet-id"
	ServiceAnnotationLoadBalancerFloatingSubnetTags   = "loadbalancer.openstack.org/floating-subnet-tags"
	ServiceAnnotationLoadBalancerClass                = "loadbalancer.openstack.org/class"
	ServiceAnnotationLoadBalancerKeepFloatingIP       = "loadbalancer.openstack.org/keep-floatingip"
	ServiceAnnotationLoadBalancerPortID               = "loadbalancer.openstack.org/port-id"
	ServiceAnnotationLoadBalancerProxyEnabled         = "loadbalancer.openstack.org/proxy-protocol"
	ServiceAnnotationLoadBalancerSubnetID             = "loadbalancer.openstack.org/subnet-id"
	ServiceAnnotationLoadBalancerNetworkID            = "loadbalancer.openstack.org/network-id"
	ServiceAnnotationLoadBalancerMemberSubnetID       = "loadbalancer.openstack.org/member-subnet-id"
	ServiceAnnotationLoadBalancerTimeoutClientData    = "loadbalancer.openstack.org/timeout-client-data"
	ServiceAnnotationLoadBalancerTimeoutMemberConnect = "loadbalancer.openstack.org/timeout-member-connect"
	ServiceAnnotationLoadBalancerTimeoutMemberData    = "loadbalancer.openstack.org/timeout-member-data"
	ServiceAnnotationLoadBalancerTimeoutTCPInspect    = "loadbalancer.openstack.org/timeout-tcp-inspect"
	ServiceAnnotationLoadBalancerXForwardedFor        = "loadbalancer.openstack.org/x-forwarded-for"
	ServiceAnnotationLoadBalancerFlavorID             = "loadbalancer.openstack.org/flavor-id"
	ServiceAnnotationLoadBalancerAvailabilityZone     = "loadbalancer.openstack.org/availability-zone"
	// ServiceAnnotationLoadBalancerEnableHealthMonitor defines whether to create health monitor for the load balancer
	// pool, if not specified, use 'create-monitor' config. The health monitor can be created or deleted dynamically.
	ServiceAnnotationLoadBalancerEnableHealthMonitor         = "loadbalancer.openstack.org/enable-health-monitor"
	ServiceAnnotationLoadBalancerHealthMonitorDelay          = "loadbalancer.openstack.org/health-monitor-delay"
	ServiceAnnotationLoadBalancerHealthMonitorTimeout        = "loadbalancer.openstack.org/health-monitor-timeout"
	ServiceAnnotationLoadBalancerHealthMonitorMaxRetries     = "loadbalancer.openstack.org/health-monitor-max-retries"
	ServiceAnnotationLoadBalancerHealthMonitorMaxRetriesDown = "loadbalancer.openstack.org/health-monitor-max-retries-down"
	ServiceAnnotationLoadBalancerLoadbalancerHostname        = "loadbalancer.openstack.org/hostname"
	ServiceAnnotationLoadBalancerAddress                     = "loadbalancer.openstack.org/load-balancer-address"
	// revive:disable:var-naming
	ServiceAnnotationTlsContainerRef = "loadbalancer.openstack.org/default-tls-container-ref"
	// revive:enable:var-naming
	// See https://nip.io
	defaultProxyHostnameSuffix         = "nip.io"
	ServiceAnnotationLoadBalancerID    = "loadbalancer.openstack.org/load-balancer-id"
	ServiceAnnotationLoadBalancerOldID = "loadbalancer.openstack.org/load-balancer-old-id"

	// Octavia resources name formats
	//k8s_svcNs_svcName 是否需要加上vip
	lbFormat       = "%s_%s_%s_%s"
	//listenerFormat = "listener_%d_%s"
	//lbName_portIndex => k8s_svcNs_svcName_portIndex
	listenerFormat = "%s_%d"
	//lbName_portIndex => k8s_svcNs_svcName_portIndex
	poolFormat     = "%s_%d"
	monitorFormat  = "monitor_%d_%s"
	// namespace_endpointSliceName_protocol_port_addressIndex
	memeberFormat = "%s_%s_%s_%d_%d"

	NamespaceAnnotationLoadBalancerMemberSubnetID = "inspur.com/pod-subnet"
)

// LbaasV2 is a LoadBalancer implementation based on Octavia
type LbaasV2 struct {
	LoadBalancer
}

// floatingSubnetSpec contains the specification of the public subnet to use for
// a public network. If given it may either describe the subnet id or
// a subnet name pattern for the subnet to use. If a pattern is given
// the first subnet matching the name pattern with an allocatable floating ip
// will be selected.
type floatingSubnetSpec struct {
	subnetID   string
	subnet     string
	subnetTags string
}

// TweakSubNetListOpsFunction is used to modify List Options for subnets
type TweakSubNetListOpsFunction func(*subnets.ListOpts)

// matcher matches a subnet
type matcher func(subnet *subnets.Subnet) bool

type servicePatcher struct {
	kclient kubernetes.Interface
	base    *corev1.Service
	updated *corev1.Service
}

var _ cloudprovider.LoadBalancer = &LbaasV2{}

// negate returns a negated matches for a given one
func negate(f matcher) matcher { return func(s *subnets.Subnet) bool { return !f(s) } }

func andMatcher(a, b matcher) matcher {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(s *subnets.Subnet) bool {
		return a(s) && b(s)
	}
}

// reexpNameMatcher creates a subnet matcher matching a subnet by name for a given regexp.
func regexpNameMatcher(r *regexp.Regexp) matcher {
	return func(s *subnets.Subnet) bool { return r.FindString(s.Name) == s.Name }
}

// subnetNameMatcher creates a subnet matcher matching a subnet by name for a given glob
// or regexp
func subnetNameMatcher(pat string) (matcher, error) {
	// try to create floating IP in matching subnets
	var match matcher
	not := false
	if strings.HasPrefix(pat, "!") {
		not = true
		pat = pat[1:]
	}
	if strings.HasPrefix(pat, "~") {
		rexp, err := regexp.Compile(pat[1:])
		if err != nil {
			return nil, fmt.Errorf("invalid subnet regexp pattern %q: %s", pat[1:], err)
		}
		match = regexpNameMatcher(rexp)
	} else {
		match = regexpNameMatcher(glob.Globexp(pat))
	}
	if not {
		match = negate(match)
	}
	return match, nil
}

// subnetTagMatcher matches a subnet by a given tag spec
func subnetTagMatcher(tags string) matcher {
	// try to create floating IP in matching subnets
	var match matcher

	list, not, all := tagList(tags)

	match = func(s *subnets.Subnet) bool {
		for _, tag := range list {
			found := false
			for _, t := range s.Tags {
				if t == tag {
					found = true
					break
				}
			}
			if found {
				if !all {
					return !not
				}
			} else {
				if all {
					return not
				}
			}
		}
		return not != all
	}
	return match
}

func (s *floatingSubnetSpec) Configured() bool {
	if s != nil && (s.subnetID != "" || s.MatcherConfigured()) {
		return true
	}
	return false
}

func (s *floatingSubnetSpec) ListSubnetsForNetwork(lbaas *LbaasV2, networkID string) ([]subnets.Subnet, error) {
	matcher, err := s.Matcher(false)
	if err != nil {
		return nil, err
	}
	list, err := lbaas.listSubnetsForNetwork(networkID, s.tweakListOpts)
	if err != nil {
		return nil, err
	}
	if matcher == nil {
		return list, nil
	}

	// filter subnets according to spec
	var foundSubnets []subnets.Subnet
	for _, subnet := range list {
		if matcher(&subnet) {
			foundSubnets = append(foundSubnets, subnet)
		}
	}
	return foundSubnets, nil
}

// tweakListOpts can be used to optimize a subnet list query for the
// actually described subnet filter
func (s *floatingSubnetSpec) tweakListOpts(opts *subnets.ListOpts) {
	if s.subnetTags != "" {
		list, not, all := tagList(s.subnetTags)
		tags := strings.Join(list, ",")
		if all {
			if not {
				opts.NotTagsAny = tags // at least one tag must be missing
			} else {
				opts.Tags = tags // all tags must be present
			}
		} else {
			if not {
				opts.NotTags = tags // none of the tags are present
			} else {
				opts.TagsAny = tags // at least one tag is present
			}
		}
	}
}

func (s *floatingSubnetSpec) MatcherConfigured() bool {
	if s != nil && s.subnetID == "" && (s.subnet != "" || s.subnetTags != "") {
		return true
	}
	return false
}

func addField(s, name, value string) string {
	if value == "" {
		return s
	}
	if s == "" {
		s += ", "
	}
	return fmt.Sprintf("%s%s: %q", s, name, value)
}

func (s *floatingSubnetSpec) String() string {
	if s == nil || (s.subnetID == "" && s.subnet == "" && s.subnetTags == "") {
		return "<none>"
	}
	pat := addField("", "subnetID", s.subnetID)
	pat = addField(pat, "pattern", s.subnet)
	return addField(pat, "tags", s.subnetTags)
}

func (s *floatingSubnetSpec) Matcher(tag bool) (matcher, error) {
	if !s.MatcherConfigured() {
		return nil, nil
	}
	var match matcher
	var err error
	if s.subnet != "" {
		match, err = subnetNameMatcher(s.subnet)
		if err != nil {
			return nil, err
		}
	}
	if tag && s.subnetTags != "" {
		match = andMatcher(match, subnetTagMatcher(s.subnetTags))
	}
	if match == nil {
		match = func(s *subnets.Subnet) bool { return true }
	}
	return match, nil
}

func tagList(tags string) ([]string, bool, bool) {
	not := strings.HasPrefix(tags, "!")
	if not {
		tags = tags[1:]
	}
	all := strings.HasPrefix(tags, "&")
	if all {
		tags = tags[1:]
	}
	list := strings.Split(tags, ",")
	for i := range list {
		list[i] = strings.TrimSpace(list[i])
	}
	return list, not, all
}

// serviceConfig contains configurations for creating a Service.
type serviceConfig struct {
	internal             bool
	connLimit            int
	configClassName      string
	lbNetworkID          string
	lbSubnetID           string
	lbMemberSubnetID     string
	lbPublicNetworkID    string
	lbPublicSubnetSpec   *floatingSubnetSpec
	keepClientIP         bool
	enableProxyProtocol  bool
	timeoutClientData    int
	timeoutMemberConnect int
	timeoutMemberData    int
	timeoutTCPInspect    int
	allowedCIDR          []string
	enableMonitor        bool
	flavorID             string
	availabilityZone     string
	tlsContainerRef      string
	lbID                 string
	// service not need loadbalance or want another loadbalance
	//oldLbID                     string
	lbName                      string
	supportLBTags               bool
	healthCheckNodePort         int
	healthMonitorDelay          int
	healthMonitorTimeout        int
	healthMonitorMaxRetries     int
	healthMonitorMaxRetriesDown int
	preferredIPFamily           corev1.IPFamily // preferred (the first) IP family indicated in service's `spec.ipFamilies`
}

type listenerKey struct {
	Protocol listeners.Protocol
	Port     int
}

// getLoadbalancerByName get the load balancer which is in valid status by the given name/legacy name.
func getLoadbalancerByName(client *gophercloud.ServiceClient, name string, legacyName string) (*loadbalancers.LoadBalancer, error) {
	var validLBs []loadbalancers.LoadBalancer

	opts := loadbalancers.ListOpts{
		Name: name,
	}
	allLoadbalancers, err := openstackutil.GetLoadBalancers(client, opts)
	if err != nil {
		return nil, err
	}

	if len(allLoadbalancers) == 0 {
		if len(legacyName) > 0 {
			// Backoff to get load balnacer by legacy name.
			opts := loadbalancers.ListOpts{
				Name: legacyName,
			}
			allLoadbalancers, err = openstackutil.GetLoadBalancers(client, opts)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, cpoerrors.ErrNotFound
		}
	}

	for _, lb := range allLoadbalancers {
		// All the ProvisioningStatus could be found here https://developer.openstack.org/api-ref/load-balancer/v2/index.html#provisioning-status-codes
		if lb.ProvisioningStatus != "DELETED" && lb.ProvisioningStatus != "PENDING_DELETE" {
			validLBs = append(validLBs, lb)
		}
	}

	if len(validLBs) > 1 {
		return nil, cpoerrors.ErrMultipleResults
	}
	if len(validLBs) == 0 {
		return nil, cpoerrors.ErrNotFound
	}

	return &validLBs[0], nil
}

func popListener(existingListeners []listeners.Listener, id string) []listeners.Listener {
	newListeners := []listeners.Listener{}
	for _, existingListener := range existingListeners {
		if existingListener.ID != id {
			newListeners = append(newListeners, existingListener)
		}
	}
	return newListeners
}

func getSecurityGroupName(service *corev1.Service) string {
	securityGroupName := fmt.Sprintf("lb-sg-%s-%s-%s", service.UID, service.Namespace, service.Name)
	//OpenStack requires that the name of a security group is shorter than 255 bytes.
	if len(securityGroupName) > 255 {
		securityGroupName = securityGroupName[:255]
	}

	return securityGroupName
}

func getSecurityGroupRules(client *gophercloud.ServiceClient, opts rules.ListOpts) ([]rules.SecGroupRule, error) {
	mc := metrics.NewMetricContext("security_group_rule", "list")
	page, err := rules.List(client, opts).AllPages()
	if mc.ObserveRequest(err) != nil {
		return nil, err
	}
	return rules.ExtractRules(page)
}

func getListenerProtocol(protocol corev1.Protocol, svcConf *serviceConfig) listeners.Protocol {
	// Make neutron-lbaas code work
	if svcConf != nil {
		if svcConf.tlsContainerRef != "" {
			return listeners.ProtocolTerminatedHTTPS
		} else if svcConf.keepClientIP {
			return listeners.ProtocolHTTP
		}
	}

	switch protocol {
	case corev1.ProtocolTCP:
		return listeners.ProtocolTCP
	case corev1.ProtocolUDP:
		return listeners.ProtocolUDP
	default:
		return listeners.Protocol(protocol)
	}
}

func (lbaas *LbaasV2) createOctaviaLoadBalancer(name, clusterName string, service *corev1.Service, nodes []*corev1.Node, svcConf *serviceConfig) (*loadbalancers.LoadBalancer, error) {
	createOpts := loadbalancers.CreateOpts{
		Name:        name,
		Description: fmt.Sprintf("Kubernetes external service %s/%s from cluster %s", service.Namespace, service.Name, clusterName),
		Provider:    lbaas.opts.LBProvider,
	}

	if svcConf.supportLBTags {
		createOpts.Tags = []string{svcConf.lbName}
	}

	if svcConf.flavorID != "" {
		createOpts.FlavorID = svcConf.flavorID
	}

	if svcConf.availabilityZone != "" {
		createOpts.AvailabilityZone = svcConf.availabilityZone
	}

	vipPort := getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerPortID, "")
	// TODO 涉及到从文件中获取的，改为cmp传递，也就是从service的注解中获取
	lbClass := lbaas.opts.LBClasses[svcConf.configClassName]

	if vipPort != "" {
		createOpts.VipPortID = vipPort
	} else {
		if lbClass != nil && lbClass.SubnetID != "" {
			createOpts.VipSubnetID = lbClass.SubnetID
		} else {
			createOpts.VipSubnetID = svcConf.lbSubnetID
		}

		if lbClass != nil && lbClass.NetworkID != "" {
			createOpts.VipNetworkID = lbClass.NetworkID
		} else if svcConf.lbNetworkID != "" {
			createOpts.VipNetworkID = svcConf.lbNetworkID
		} else {
			klog.V(4).Infof("network-id parameter not passed, it will be inferred from subnet-id")
		}
	}

	// For external load balancer, the LoadBalancerIP is a public IP address.
	loadBalancerIP := service.Spec.LoadBalancerIP
	if loadBalancerIP != "" && svcConf.internal {
		createOpts.VipAddress = loadBalancerIP
	}

	if !lbaas.opts.ProviderRequiresSerialAPICalls {
		for portIndex, port := range service.Spec.Ports {
			listenerCreateOpt := lbaas.buildListenerCreateOpt(port, svcConf, cpoutil.Sprintf255(listenerFormat, name, portIndex ))
			members, newMembers, err := lbaas.buildBatchUpdateMemberOpts(port, nodes, svcConf, nil)
			if err != nil {
				return nil, err
			}
			poolCreateOpt := lbaas.buildPoolCreateOpt(string(listenerCreateOpt.Protocol), service, svcConf, cpoutil.Sprintf255(poolFormat, portIndex, name))
			poolCreateOpt.Members = members
			// Pool name must be provided to create fully populated loadbalancer
			var withHealthMonitor string
			if svcConf.enableMonitor {
				opts := lbaas.buildMonitorCreateOpts(svcConf, port, cpoutil.Sprintf255(monitorFormat, portIndex, name))
				poolCreateOpt.Monitor = &opts
				withHealthMonitor = " with healthmonitor"
			}

			listenerCreateOpt.DefaultPool = &poolCreateOpt
			createOpts.Listeners = append(createOpts.Listeners, listenerCreateOpt)
			klog.V(2).Infof("Loadbalancer %s: adding pool%s using protocol %s with %d members", name, withHealthMonitor, poolCreateOpt.Protocol, len(newMembers))
		}
	}

	mc := metrics.NewMetricContext("loadbalancer", "create")
	loadbalancer, err := loadbalancers.Create(lbaas.lb, createOpts).Extract()
	if mc.ObserveRequest(err) != nil {
		var printObj interface{} = createOpts
		if opts, err := json.Marshal(createOpts); err == nil {
			printObj = string(opts)
		}
		return nil, fmt.Errorf("error creating loadbalancer %v: %v", printObj, err)
	}

	// In case subnet ID is not configured
	if svcConf.lbMemberSubnetID == "" {
		svcConf.lbMemberSubnetID = loadbalancer.VipSubnetID
	}

	if loadbalancer, err = openstackutil.WaitActiveAndGetLoadBalancer(lbaas.lb, loadbalancer.ID); err != nil {
		return nil, err
	}

	return loadbalancer, nil
}

// GetLoadBalancer returns whether the specified load balancer exists and its status
func (lbaas *LbaasV2) GetLoadBalancer(ctx context.Context, clusterName string, service *corev1.Service) (*corev1.LoadBalancerStatus, bool, error) {
	name := lbaas.GetLoadBalancerName(ctx, clusterName, service)
	legacyName := lbaas.getLoadBalancerLegacyName(ctx, clusterName, service)
	lbID := getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerID, "")
	var loadbalancer *loadbalancers.LoadBalancer
	var err error

	if lbID != "" {
		loadbalancer, err = openstackutil.GetLoadbalancerByID(lbaas.lb, lbID)
	} else {
		loadbalancer, err = getLoadbalancerByName(lbaas.lb, name, legacyName)
	}
	if err != nil && cpoerrors.IsNotFound(err) {
		return nil, false, nil
	}
	if loadbalancer == nil {
		return nil, false, err
	}

	status := &corev1.LoadBalancerStatus{}
	portID := loadbalancer.VipPortID
	if portID != "" {
		floatIP, err := openstackutil.GetFloatingIPByPortID(lbaas.network, portID)
		if err != nil {
			return nil, false, fmt.Errorf("failed when trying to get floating IP for port %s: %v", portID, err)
		}
		if floatIP != nil {
			status.Ingress = []corev1.LoadBalancerIngress{{IP: floatIP.FloatingIP}}
		} else {
			status.Ingress = []corev1.LoadBalancerIngress{{IP: loadbalancer.VipAddress}}
		}
	}

	return status, true, nil
}

// GetLoadBalancerName returns the constructed load balancer name.
func (lbaas *LbaasV2) GetLoadBalancerName(_ context.Context, lbName string, service *corev1.Service) string {
	return cpoutil.Sprintf255(lbFormat, servicePrefix, serviceClusterId ,service.Namespace, service.Name)
}

// getLoadBalancerLegacyName returns the legacy load balancer name for backward compatibility.
func (lbaas *LbaasV2) getLoadBalancerLegacyName(_ context.Context, _ string, service *corev1.Service) string {
	return cloudprovider.DefaultLoadBalancerName(service)
}

// The LB needs to be configured with instance addresses on the same
// subnet as the LB (aka opts.SubnetID). Currently, we're just
// guessing that the node's InternalIP is the right address.
// In case no InternalIP can be found, ExternalIP is tried.
// If neither InternalIP nor ExternalIP can be found an error is
// returned.
// If preferredIPFamily is specified, only address of the specified IP family can be returned.
func nodeAddressForLB(node *corev1.Node, preferredIPFamily corev1.IPFamily) (string, error) {
	addrs := node.Status.Addresses
	if len(addrs) == 0 {
		return "", cpoerrors.ErrNoAddressFound
	}

	allowedAddrTypes := []corev1.NodeAddressType{corev1.NodeInternalIP, corev1.NodeExternalIP}

	for _, allowedAddrType := range allowedAddrTypes {
		for _, addr := range addrs {
			if addr.Type == allowedAddrType {
				switch preferredIPFamily {
				case corev1.IPv4Protocol:
					if netutils.IsIPv4String(addr.Address) {
						return addr.Address, nil
					}
				case corev1.IPv6Protocol:
					if netutils.IsIPv6String(addr.Address) {
						return addr.Address, nil
					}
				default:
					return addr.Address, nil
				}
			}
		}
	}

	return "", cpoerrors.ErrNoAddressFound
}

// getNamespaceFromServiceAnnotation searches a given v1.namespace for a specific annotationKey and either returns the annotation's value or a specified defaultSetting
func getNamespaceFromServiceAnnotation(namespace *corev1.Namespace, annotationKey string, defaultSetting string) string {
	klog.V(4).Infof("getNamespaceFromServiceAnnotation(%s, %v, %v)", namespace.Name, annotationKey, defaultSetting)
	if annotationValue, ok := namespace.Annotations[annotationKey]; ok {
		//if there is an annotation for this setting, set the "setting" var to it
		// annotationValue can be empty, it is working as designed
		// it makes possible for instance provisioning loadbalancer without floatingip
		klog.V(4).Infof("Found a Namespace Annotation: %v = %v", annotationKey, annotationValue)
		return annotationValue
	}
	//if there is no annotation, set "settings" var to the value from cloud config
	if defaultSetting != "" {
		klog.V(4).Infof("Could not find a Namespace Annotation; falling back on cloud-config setting: %v = %v", annotationKey, defaultSetting)
	}
	return defaultSetting
}

// getIntFromServiceAnnotation searches a given v1.Service for a specific annotationKey and either returns the annotation's integer value or a specified defaultSetting
func getIntFromServiceAnnotation(service *corev1.Service, annotationKey string, defaultSetting int) int {
	klog.V(4).Infof("getIntFromServiceAnnotation(%s/%s, %v, %v)", service.Namespace, service.Name, annotationKey, defaultSetting)
	if annotationValue, ok := service.Annotations[annotationKey]; ok {
		returnValue, err := strconv.Atoi(annotationValue)
		if err != nil {
			klog.Warningf("Could not parse int value from %q, failing back to default %s = %v, %v", annotationValue, annotationKey, defaultSetting, err)
			return defaultSetting
		}

		klog.V(4).Infof("Found a Service Annotation: %v = %v", annotationKey, annotationValue)
		return returnValue
	}
	klog.V(4).Infof("Could not find a Service Annotation; falling back to default setting: %v = %v", annotationKey, defaultSetting)
	return defaultSetting
}

// getBoolFromServiceAnnotation searches a given v1.Service for a specific annotationKey and either returns the annotation's boolean value or a specified defaultSetting
func getBoolFromServiceAnnotation(service *corev1.Service, annotationKey string, defaultSetting bool) bool {
	klog.V(4).Infof("getBoolFromServiceAnnotation(%s/%s, %v, %v)", service.Namespace, service.Name, annotationKey, defaultSetting)
	if annotationValue, ok := service.Annotations[annotationKey]; ok {
		returnValue := false
		switch annotationValue {
		case "true":
			returnValue = true
		case "false":
			returnValue = false
		default:
			returnValue = defaultSetting
		}

		klog.V(4).Infof("Found a Service Annotation: %v = %v", annotationKey, returnValue)
		return returnValue
	}
	klog.V(4).Infof("Could not find a Service Annotation; falling back to default setting: %v = %v", annotationKey, defaultSetting)
	return defaultSetting
}

// getSubnetIDForLB returns subnet-id for a specific node
func getSubnetIDForLB(network *gophercloud.ServiceClient, node corev1.Node, preferredIPFamily corev1.IPFamily) (string, error) {
	ipAddress, err := nodeAddressForLB(&node, preferredIPFamily)
	if err != nil {
		return "", err
	}

	_, instanceID, err := instanceIDFromProviderID(node.Spec.ProviderID)
	if err != nil {
		return "", fmt.Errorf("can't determine instance ID from ProviderID when autodetecting LB subnet: %w", err)
	}

	ports, err := getAttachedPorts(network, instanceID)
	if err != nil {
		return "", err
	}

	for _, port := range ports {
		for _, fixedIP := range port.FixedIPs {
			if fixedIP.IPAddress == ipAddress {
				return fixedIP.SubnetID, nil
			}
		}
	}

	return "", cpoerrors.ErrNotFound
}

// isPortMember returns true if IP and subnetID are one of the FixedIPs on the port
func isPortMember(port PortWithPortSecurity, IP string, subnetID string) bool {
	for _, fixedIP := range port.FixedIPs {
		if (subnetID == "" || subnetID == fixedIP.SubnetID) && IP == fixedIP.IPAddress {
			return true
		}
	}
	return false
}

// applyNodeSecurityGroupIDForLB associates the security group with the ports being members of the LB on the nodes.
func applyNodeSecurityGroupIDForLB(network *gophercloud.ServiceClient, svcConf *serviceConfig, nodes []*corev1.Node, sg string) error {
	for _, node := range nodes {
		serverID, _, err := instanceIDFromProviderID(node.Spec.ProviderID)
		if err != nil {
			return fmt.Errorf("error getting server ID from the node: %w", err)
		}

		addr, _ := nodeAddressForLB(node, svcConf.preferredIPFamily)
		if addr == "" {
			// If node has no viable address let's ignore it.
			continue
		}

		listOpts := neutronports.ListOpts{DeviceID: serverID}
		allPorts, err := openstackutil.GetPorts[PortWithPortSecurity](network, listOpts)
		if err != nil {
			return err
		}

		for _, port := range allPorts {
			// You can't assign an SG to a port with port_security_enabled=false, skip them.
			if !port.PortSecurityEnabled {
				continue
			}

			// If the Security Group is already present on the port, skip it.
			if slices.Contains(port.SecurityGroups, sg) {
				continue
			}

			// Only add SGs to the port actually attached to the LB
			if !isPortMember(port, addr, svcConf.lbMemberSubnetID) {
				continue
			}

			// Add the security group ID as a tag to the port in order to find all these ports when removing the security group.
			// We're doing that before actually applying the SG as if tagging would fail we wouldn't be able to find the port
			// when deleting the SG and operation would be stuck forever. It's better to find more ports than not all of them.
			mc := metrics.NewMetricContext("port_tag", "add")
			err := neutrontags.Add(network, "ports", port.ID, sg).ExtractErr()
			if mc.ObserveRequest(err) != nil {
				return fmt.Errorf("failed to add tag %s to port %s: %v", sg, port.ID, err)
			}

			// Add the SG to the port
			// TODO(dulek): This isn't an atomic operation. In order to protect from lost update issues we should use
			//              `revision_number` handling to make sure our update to `security_groups` field wasn't preceded
			//              by a different one. Same applies to a removal of the SG.
			newSGs := append(port.SecurityGroups, sg)
			updateOpts := neutronports.UpdateOpts{SecurityGroups: &newSGs}
			mc = metrics.NewMetricContext("port", "update")
			res := neutronports.Update(network, port.ID, updateOpts)
			if mc.ObserveRequest(res.Err) != nil {
				return fmt.Errorf("failed to update security group for port %s: %v", port.ID, res.Err)
			}
		}
	}

	return nil
}

// disassociateSecurityGroupForLB removes the given security group from the ports
func disassociateSecurityGroupForLB(network *gophercloud.ServiceClient, sg string) error {
	// Find all the ports that have the security group associated.
	listOpts := neutronports.ListOpts{TagsAny: sg}
	allPorts, err := openstackutil.GetPorts[neutronports.Port](network, listOpts)
	if err != nil {
		return err
	}

	// Disassocate security group and remove the tag.
	for _, port := range allPorts {
		existingSGs := sets.NewString()
		for _, sgID := range port.SecurityGroups {
			existingSGs.Insert(sgID)
		}
		existingSGs.Delete(sg)

		// Update port security groups
		newSGs := existingSGs.List()
		updateOpts := neutronports.UpdateOpts{SecurityGroups: &newSGs}
		mc := metrics.NewMetricContext("port", "update")
		res := neutronports.Update(network, port.ID, updateOpts)
		if mc.ObserveRequest(res.Err) != nil {
			return fmt.Errorf("failed to update security group for port %s: %v", port.ID, res.Err)
		}
		// Remove the security group ID tag from the port.
		mc = metrics.NewMetricContext("port_tag", "delete")
		err := neutrontags.Delete(network, "ports", port.ID, sg).ExtractErr()
		if mc.ObserveRequest(err) != nil {
			return fmt.Errorf("failed to remove tag %s to port %s: %v", sg, port.ID, res.Err)
		}
	}

	return nil
}

// deleteListeners deletes listeners and its default pool.
func (lbaas *LbaasV2) deleteListeners(lbID string, listenerList []listeners.Listener) error {
	for _, listener := range listenerList {
		klog.InfoS("Deleting listener", "listenerID", listener.ID, "lbID", lbID)

		pool, err := openstackutil.GetPoolByListener(lbaas.lb, lbID, listener.ID)
		if err != nil && err != cpoerrors.ErrNotFound {
			return fmt.Errorf("error getting pool for obsolete listener %s: %v", listener.ID, err)
		}
		if pool != nil {
			klog.InfoS("Deleting pool", "poolID", pool.ID, "listenerID", listener.ID, "lbID", lbID)
			// Delete pool automatically deletes all its members.
			if err := openstackutil.DeletePool(lbaas.lb, pool.ID, lbID); err != nil {
				return err
			}
			klog.InfoS("Deleted pool", "poolID", pool.ID, "listenerID", listener.ID, "lbID", lbID)
		}

		if err := openstackutil.DeleteListener(lbaas.lb, listener.ID, lbID); err != nil {
			return err
		}
		klog.InfoS("Deleted listener", "listenerID", listener.ID, "lbID", lbID)
	}

	return nil
}

// deleteOctaviaListeners is used not simply for deleting listeners but only deleting listeners used to be created by the Service.
func (lbaas *LbaasV2) deleteOctaviaListeners(lbID string, listenerList []listeners.Listener, isLBOwner bool, lbName string) error {
	for _, listener := range listenerList {
		// If the listener was created by this Service before or after supporting shared LB.
		if (isLBOwner && len(listener.Tags) == 0) || cpoutil.Contains(listener.Tags, lbName) {
			klog.InfoS("Deleting listener", "listenerID", listener.ID, "lbID", lbID)

			pool, err := openstackutil.GetPoolByListener(lbaas.lb, lbID, listener.ID)
			if err != nil && err != cpoerrors.ErrNotFound {
				return fmt.Errorf("error getting pool for listener %s: %v", listener.ID, err)
			}
			if pool != nil {
				klog.InfoS("Deleting pool", "poolID", pool.ID, "listenerID", listener.ID, "lbID", lbID)

				// Delete pool automatically deletes all its members.
				if err := openstackutil.DeletePool(lbaas.lb, pool.ID, lbID); err != nil {
					return err
				}
				klog.InfoS("Deleted pool", "poolID", pool.ID, "listenerID", listener.ID, "lbID", lbID)
			}

			if err := openstackutil.DeleteListener(lbaas.lb, listener.ID, lbID); err != nil {
				return err
			}

			klog.InfoS("Deleted listener", "listenerID", listener.ID, "lbID", lbID)
		} else {
			// This listener is created and managed by others, shouldn't delete.
			klog.V(4).InfoS("Ignoring the listener used by others", "listenerID", listener.ID, "loadbalancerID", lbID, "tags", listener.Tags)
			continue
		}
	}

	return nil
}

func (lbaas *LbaasV2) createFloatingIP(msg string, floatIPOpts floatingips.CreateOpts) (*floatingips.FloatingIP, error) {
	klog.V(4).Infof("%s floating ip with opts %+v", msg, floatIPOpts)
	mc := metrics.NewMetricContext("floating_ip", "create")
	floatIP, err := floatingips.Create(lbaas.network, floatIPOpts).Extract()
	err = PreserveGopherError(err)
	if mc.ObserveRequest(err) != nil {
		return floatIP, fmt.Errorf("error creating LB floatingip: %s", err)
	}
	return floatIP, err
}

func (lbaas *LbaasV2) updateFloatingIP(floatingip *floatingips.FloatingIP, portID *string) (*floatingips.FloatingIP, error) {
	floatUpdateOpts := floatingips.UpdateOpts{
		PortID: portID,
	}
	if portID != nil {
		klog.V(4).Infof("Attaching floating ip %q to loadbalancer port %q", floatingip.FloatingIP, portID)
	} else {
		klog.V(4).Infof("Detaching floating ip %q from port %q", floatingip.FloatingIP, floatingip.PortID)
	}
	mc := metrics.NewMetricContext("floating_ip", "update")
	floatingip, err := floatingips.Update(lbaas.network, floatingip.ID, floatUpdateOpts).Extract()
	if mc.ObserveRequest(err) != nil {
		return nil, fmt.Errorf("error updating LB floatingip %+v: %v", floatUpdateOpts, err)
	}
	return floatingip, nil
}

// ensureFloatingIP manages a FIP for a Service and returns the address that should be advertised in the
// .Status.LoadBalancer. In particular it will:
//  1. Lookup if any FIP is already attached to the VIP port of the LB.
//     a) If it is and Service is internal, it will attempt to detach the FIP and delete it if it was created
//     by cloud provider. This is to support cases of changing the internal annotation.
//     b) If the Service is not the owner of the LB it will not contiue to prevent accidental exposure of the
//     possible internal Services already existing on that LB.
//     c) If it's external Service, it will use that existing FIP.
//  2. Lookup FIP specified in Spec.LoadBalancerIP and try to assign it to the LB VIP port.
//  3. Try to create and assign a new FIP:
//     a) If Spec.LoadBalancerIP is not set, just create a random FIP in the external network and use that.
//     b) If Spec.LoadBalancerIP is specified, try to create a FIP with that address. By default this is not allowed by
//     the Neutron policy for regular users!
func (lbaas *LbaasV2) ensureFloatingIP(clusterName string, service *corev1.Service, lb *loadbalancers.LoadBalancer, svcConf *serviceConfig, isLBOwner bool) (string, error) {
	serviceName := fmt.Sprintf("%s/%s", service.Namespace, service.Name)

	// We need to fetch the FIP attached to load balancer's VIP port for both codepaths
	portID := lb.VipPortID
	floatIP, err := openstackutil.GetFloatingIPByPortID(lbaas.network, portID)
	if err != nil {
		return "", fmt.Errorf("failed when getting floating IP for port %s: %v", portID, err)
	}

	if floatIP != nil {
		klog.V(4).Infof("Found floating ip %v by loadbalancer port id %q", floatIP, portID)
	}

	if svcConf.internal && isLBOwner {
		// if we found a FIP, this is an internal service and we are the owner we should attempt to delete it
		if floatIP != nil {
			keepFloatingAnnotation := getBoolFromServiceAnnotation(service, ServiceAnnotationLoadBalancerKeepFloatingIP, false)
			fipDeleted := false
			if !keepFloatingAnnotation {
				klog.V(4).Infof("Deleting floating IP %v attached to loadbalancer port id %q for internal service %s", floatIP, portID, serviceName)
				fipDeleted, err = lbaas.deleteFIPIfCreatedByProvider(floatIP, portID, service)
				if err != nil {
					return "", err
				}
			}
			if !fipDeleted {
				// if FIP wasn't deleted (because of keep-floatingip annotation or not being created by us) we should still detach it
				_, err = lbaas.updateFloatingIP(floatIP, nil)
				if err != nil {
					return "", err
				}
			}
		}
		return lb.VipAddress, nil
	}

	// first attempt: if we've found a FIP attached to LBs VIP port, we'll be using that.

	// we cannot add a FIP to a shared LB when we're a secondary Service or we risk adding it to an internal
	// Service and exposing it to the world unintentionally.
	if floatIP == nil && !isLBOwner {
		return "", fmt.Errorf("cannot attach a floating IP to a load balancer for a shared Service %s/%s, only owner Service can do that",
			service.Namespace, service.Name)
	}

	// second attempt: fetch floating IP specified in service Spec.LoadBalancerIP
	// if found, associate floating IP with loadbalancer's VIP port
	loadBalancerIP := service.Spec.LoadBalancerIP
	if floatIP == nil && loadBalancerIP != "" {
		opts := floatingips.ListOpts{
			FloatingIP: loadBalancerIP,
		}
		existingIPs, err := openstackutil.GetFloatingIPs(lbaas.network, opts)
		if err != nil {
			return "", fmt.Errorf("failed when trying to get existing floating IP %s, error: %v", loadBalancerIP, err)
		}
		klog.V(4).Infof("Found floating ips %v by loadbalancer ip %q", existingIPs, loadBalancerIP)

		if len(existingIPs) > 0 {
			floatingip := existingIPs[0]
			if len(floatingip.PortID) == 0 {
				floatIP, err = lbaas.updateFloatingIP(&floatingip, &portID)
				if err != nil {
					return "", err
				}
			} else {
				return "", fmt.Errorf("floating IP %s is not available", loadBalancerIP)
			}
		}
	}

	// third attempt: create a new floating IP
	if floatIP == nil {
		if svcConf.lbPublicNetworkID != "" {
			klog.V(2).Infof("Creating floating IP %s for loadbalancer %s", loadBalancerIP, lb.ID)

			floatIPOpts := floatingips.CreateOpts{
				FloatingNetworkID: svcConf.lbPublicNetworkID,
				PortID:            portID,
				Description:       fmt.Sprintf("Floating IP for Kubernetes external service %s from cluster %s", serviceName, clusterName),
			}

			if loadBalancerIP == "" && svcConf.lbPublicSubnetSpec.MatcherConfigured() {
				var foundSubnet subnets.Subnet
				// tweak list options for tags
				foundSubnets, err := svcConf.lbPublicSubnetSpec.ListSubnetsForNetwork(lbaas, svcConf.lbPublicNetworkID)
				if err != nil {
					return "", err
				}
				if len(foundSubnets) == 0 {
					return "", fmt.Errorf("no subnet matching %s found for network %s",
						svcConf.lbPublicSubnetSpec, svcConf.lbPublicNetworkID)
				}

				// try to create floating IP in matching subnets (tags already filtered by list options)
				klog.V(4).Infof("found %d subnets matching %s for network %s", len(foundSubnets),
					svcConf.lbPublicSubnetSpec, svcConf.lbPublicNetworkID)
				for _, subnet := range foundSubnets {
					floatIPOpts.SubnetID = subnet.ID
					floatIP, err = lbaas.createFloatingIP(fmt.Sprintf("Trying subnet %s for creating", subnet.Name), floatIPOpts)
					if err == nil {
						foundSubnet = subnet
						break
					}
					klog.V(2).Infof("cannot use subnet %s: %s", subnet.Name, err)
				}
				if err != nil {
					return "", fmt.Errorf("no free subnet matching %q found for network %s (last error %s)",
						svcConf.lbPublicSubnetSpec, svcConf.lbPublicNetworkID, err)
				}
				klog.V(2).Infof("Successfully created floating IP %s for loadbalancer %s on subnet %s(%s)", floatIP.FloatingIP, lb.ID, foundSubnet.Name, foundSubnet.ID)
			} else {
				if svcConf.lbPublicSubnetSpec != nil {
					floatIPOpts.SubnetID = svcConf.lbPublicSubnetSpec.subnetID
				}
				floatIPOpts.FloatingIP = loadBalancerIP
				floatIP, err = lbaas.createFloatingIP("Creating", floatIPOpts)
				if err != nil {
					return "", err
				}
				klog.V(2).Infof("Successfully created floating IP %s for loadbalancer %s", floatIP.FloatingIP, lb.ID)
			}

		} else {
			klog.Warningf("Floating network configuration not provided for Service %s, forcing to ensure an internal load balancer service", serviceName)
		}
	}

	if floatIP != nil {
		return floatIP.FloatingIP, nil
	}

	return lb.VipAddress, nil
}

func (lbaas *LbaasV2) ensureOctaviaHealthMonitor(lbID string, name string, pool *v2pools.Pool, port corev1.ServicePort, svcConf *serviceConfig) error {
	monitorID := pool.MonitorID

	if monitorID == "" {
		// do nothing
		if !svcConf.enableMonitor {
			return nil
		}

		// a new monitor must be created
		klog.V(2).Infof("Creating monitor for pool %s", pool.ID)
		createOpts := lbaas.buildMonitorCreateOpts(svcConf, port, name)
		return lbaas.createOctaviaHealthMonitor(createOpts, pool.ID, lbID)
	}

	// an existing monitor must be deleted
	if !svcConf.enableMonitor {
		klog.Infof("Deleting health monitor %s for pool %s", monitorID, pool.ID)
		return openstackutil.DeleteHealthMonitor(lbaas.lb, monitorID, lbID)
	}

	// get an existing monitor status
	monitor, err := openstackutil.GetHealthMonitor(lbaas.lb, monitorID)
	if err != nil {
		// return err on 404 is ok, since we get monitorID dynamically from the pool
		return err
	}

	// recreate health monitor with a new type
	createOpts := lbaas.buildMonitorCreateOpts(svcConf, port, name)
	if createOpts.Type != monitor.Type {
		klog.InfoS("Recreating health monitor for the pool", "pool", pool.ID, "oldMonitor", monitorID)
		if err := openstackutil.DeleteHealthMonitor(lbaas.lb, monitorID, lbID); err != nil {
			return err
		}
		return lbaas.createOctaviaHealthMonitor(createOpts, pool.ID, lbID)
	}

	// update new monitor parameters
	if name != monitor.Name ||
		svcConf.healthMonitorDelay != monitor.Delay ||
		svcConf.healthMonitorTimeout != monitor.Timeout ||
		svcConf.healthMonitorMaxRetries != monitor.MaxRetries ||
		svcConf.healthMonitorMaxRetriesDown != monitor.MaxRetriesDown {
		updateOpts := v2monitors.UpdateOpts{
			Name:           &name,
			Delay:          svcConf.healthMonitorDelay,
			Timeout:        svcConf.healthMonitorTimeout,
			MaxRetries:     svcConf.healthMonitorMaxRetries,
			MaxRetriesDown: svcConf.healthMonitorMaxRetriesDown,
		}
		klog.Infof("Updating health monitor %s updateOpts %+v", monitorID, updateOpts)
		return openstackutil.UpdateHealthMonitor(lbaas.lb, monitorID, updateOpts, lbID)
	}

	return nil
}

func (lbaas *LbaasV2) canUseHTTPMonitor(port corev1.ServicePort) bool {
	if lbaas.opts.LBProvider == "ovn" {
		// ovn-octavia-provider doesn't support HTTP monitors at all. We got to avoid creating it with ovn.
		return false
	}

	if port.Protocol == corev1.ProtocolUDP {
		// Older Octavia versions or OVN provider doesn't support HTTP monitors on UDP pools. We got to check if that's the case.
		return openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureHTTPMonitorsOnUDP, lbaas.opts.LBProvider)
	}

	return true
}

// buildMonitorCreateOpts returns a v2monitors.CreateOpts without PoolID for consumption of both, fully popuplated Loadbalancers and Monitors.
func (lbaas *LbaasV2) buildMonitorCreateOpts(svcConf *serviceConfig, port corev1.ServicePort, name string) v2monitors.CreateOpts {
	opts := v2monitors.CreateOpts{
		Name:           name,
		Type:           string(port.Protocol),
		Delay:          svcConf.healthMonitorDelay,
		Timeout:        svcConf.healthMonitorTimeout,
		MaxRetries:     svcConf.healthMonitorMaxRetries,
		MaxRetriesDown: svcConf.healthMonitorMaxRetriesDown,
	}
	if port.Protocol == corev1.ProtocolUDP {
		opts.Type = "UDP-CONNECT"
	}
	if svcConf.healthCheckNodePort > 0 && lbaas.canUseHTTPMonitor(port) {
		opts.Type = "HTTP"
		opts.URLPath = "/healthz"
		opts.HTTPMethod = "GET"
		opts.ExpectedCodes = "200"
	}
	return opts
}

func (lbaas *LbaasV2) createOctaviaHealthMonitor(createOpts v2monitors.CreateOpts, poolID, lbID string) error {
	// populate PoolID, attribute is omitted for consumption of the createOpts for fully populated Loadbalancer
	createOpts.PoolID = poolID
	monitor, err := openstackutil.CreateHealthMonitor(lbaas.lb, createOpts, lbID)
	if err != nil {
		return err
	}
	klog.Infof("Health monitor %s for pool %s created.", monitor.ID, poolID)

	return nil
}

// Make sure the pool is created for the Service, nodes are added as pool members.
func (lbaas *LbaasV2) ensureOctaviaPool(lbID string, name string, listener *listeners.Listener, service *corev1.Service, port corev1.ServicePort, nodes []*corev1.Node, svcConf *serviceConfig, memberOpts map[int][]v2pools.BatchUpdateMemberOpts) (*v2pools.Pool, error) {
	pool, err := openstackutil.GetPoolByListener(lbaas.lb, lbID, listener.ID)
	if err != nil && err != cpoerrors.ErrNotFound {
		return nil, fmt.Errorf("error getting pool for listener %s: %v", listener.ID, err)
	}

	// By default, use the protocol of the listener
	poolProto := v2pools.Protocol(listener.Protocol)
	if svcConf.enableProxyProtocol {
		// 默认false
		poolProto = v2pools.ProtocolPROXY
	} else if (svcConf.keepClientIP || svcConf.tlsContainerRef != "") && poolProto != v2pools.ProtocolHTTP {
		poolProto = v2pools.ProtocolHTTP
	}

	// Delete the pool and its members if it already exists and has the wrong protocol
	if pool != nil && v2pools.Protocol(pool.Protocol) != poolProto {
		klog.InfoS("Deleting unused pool", "poolID", pool.ID, "listenerID", listener.ID, "lbID", lbID)

		// Delete pool automatically deletes all its members.
		if err := openstackutil.DeletePool(lbaas.lb, pool.ID, lbID); err != nil {
			return nil, err
		}
		pool = nil
	}

	if pool == nil {
		// creat情况
		createOpt := lbaas.buildPoolCreateOpt(listener.Protocol, service, svcConf, name)
		createOpt.ListenerID = listener.ID
		createOpt.Tags = []string{name}
		klog.InfoS("Creating pool", "listenerID", listener.ID, "protocol", createOpt.Protocol)
		pool, err = openstackutil.CreatePool(lbaas.lb, createOpt, lbID)
		if err != nil {
			return nil, err
		}
		klog.V(2).Infof("Pool %s created for listener %s", pool.ID, listener.ID)
	}

	if lbaas.opts.ProviderRequiresSerialAPICalls {
		klog.V(2).Infof("Using serial API calls to update members for pool %s", pool.ID)
		var nodePort int = int(port.NodePort)

		if err := openstackutil.SeriallyReconcilePoolMembers(lbaas.lb, pool, nodePort, lbID, nodes); err != nil {
			return nil, err
		}
		return pool, nil
	}

	// TODO get old memeber
	curMembers := sets.New[string]()
	poolMembers, err := openstackutil.GetMembersbyPool(lbaas.lb, pool.ID)
	if err != nil {
		klog.Errorf("failed to get members in the pool %s: %v", pool.ID, err)
	}
	for _, m := range poolMembers {
		curMembers.Insert(fmt.Sprintf("%s-%s-%d-%d", m.Name, m.Address, m.ProtocolPort, m.MonitorPort))
	}

	// TODO 第一版本暂不开启 ServiceAnnotationLoadBalancerEnableHealthMonitor
	members, newMembers, err := lbaas.buildBatchUpdateMemberOpts(port, nodes, svcConf, memberOpts)
	if err != nil {
		return nil, err
	}
	klog.V(1).Infof("curMembers is: %v, newMembers is %v", curMembers, newMembers)
	if !curMembers.Equal(newMembers) {
		klog.V(2).Infof("Updating %d members for pool %s", len(members), pool.ID)
		if err := openstackutil.BatchUpdatePoolMembers(lbaas.lb, lbID, pool.ID, members); err != nil {
			return nil, err
		}
		klog.V(2).Infof("Successfully updated %d members for pool %s", len(members), pool.ID)
	}

	return pool, nil
}

func (lbaas *LbaasV2) buildPoolCreateOpt(listenerProtocol string, service *corev1.Service, svcConf *serviceConfig, name string) v2pools.CreateOpts {
	// By default, use the protocol of the listener
	poolProto := v2pools.Protocol(listenerProtocol)
	if svcConf.enableProxyProtocol {
		poolProto = v2pools.ProtocolPROXY
	} else if (svcConf.keepClientIP || svcConf.tlsContainerRef != "") && poolProto != v2pools.ProtocolHTTP {
		if svcConf.keepClientIP && svcConf.tlsContainerRef != "" {
			klog.V(4).Infof("Forcing to use %q protocol for pool because annotations %q %q are set", v2pools.ProtocolHTTP, ServiceAnnotationLoadBalancerXForwardedFor, ServiceAnnotationTlsContainerRef)
		} else if svcConf.keepClientIP {
			klog.V(4).Infof("Forcing to use %q protocol for pool because annotation %q is set", v2pools.ProtocolHTTP, ServiceAnnotationLoadBalancerXForwardedFor)
		} else {
			klog.V(4).Infof("Forcing to use %q protocol for pool because annotations %q is set", v2pools.ProtocolHTTP, ServiceAnnotationTlsContainerRef)
		}
		poolProto = v2pools.ProtocolHTTP
	}

	affinity := service.Spec.SessionAffinity
	var persistence *v2pools.SessionPersistence
	switch affinity {
	case corev1.ServiceAffinityNone:
		persistence = nil
	case corev1.ServiceAffinityClientIP:
		persistence = &v2pools.SessionPersistence{Type: "SOURCE_IP"}
	}

	lbmethod := v2pools.LBMethod(lbaas.opts.LBMethod)
	return v2pools.CreateOpts{
		Name:        name,
		Protocol:    poolProto,
		LBMethod:    lbmethod,
		Persistence: persistence,
	}
}

// TODO address改为endpoint获取
// buildBatchUpdateMemberOpts returns v2pools.BatchUpdateMemberOpts array for Services and Nodes alongside a list of member names
func (lbaas *LbaasV2) buildBatchUpdateMemberOpts(port corev1.ServicePort, nodes []*corev1.Node, svcConf *serviceConfig, allMembers map[int][]v2pools.BatchUpdateMemberOpts) ([]v2pools.BatchUpdateMemberOpts, sets.Set[string], error) {
	var members []v2pools.BatchUpdateMemberOpts
	newMembers := sets.New[string]()

	if len(allMembers) == 0 {
		return members, newMembers, nil
	}

	if  port.Port == 0 || port.TargetPort.IntValue() == 0 {
		klog.V(4).Infof("port is err,port.Port:%v,port.TargetPort.IntValue():%v", port.Port, port.TargetPort)
		return members, newMembers, nil
	}

	member := allMembers[port.TargetPort.IntValue()]
	if len(member) == 0 {
		return members, newMembers, nil
	}

	members = append(members, member...)
	newMembers.Insert(fmt.Sprintf("%s-%d-%d-%d", member[0].Name, member[0].Address, member[0].ProtocolPort, len(members)))
	//newMembers.Insert(fmt.Sprintf("%s-%s-%d-%d", node.Name, addr, member.ProtocolPort, svcConf.healthCheckNodePort))
	return members, newMembers, nil
}

// Make sure the listener is created for Service
func (lbaas *LbaasV2) ensureOctaviaListener(lbID string, name string, curListenerMapping map[listenerKey]*listeners.Listener, port corev1.ServicePort, svcConf *serviceConfig, _ *corev1.Service) (*listeners.Listener, error) {
	// name: listener_【portIndex】_【LBName】例如： listener_【portIndex】_kube_service_[clusterName]_[Namespace]_[serviceName]
	// TODO 已存在的listener会抛错,此处默认都不存在
	listener, isPresent := curListenerMapping[listenerKey{
		Protocol: getListenerProtocol(port.Protocol, svcConf),
		Port:     int(port.Port),
	}]
	if !isPresent {
		// 前边已经校验过，listener默认不存在,但是更新时时有listener
		listenerCreateOpt := lbaas.buildListenerCreateOpt(port, svcConf, name)
		listenerCreateOpt.LoadbalancerID = lbID
		listenerCreateOpt.Tags = []string{name}
		klog.V(2).Infof("Creating listener for port %d using protocol %s", int(port.Port), listenerCreateOpt.Protocol)

		var err error
		listener, err = openstackutil.CreateListener(lbaas.lb, lbID, listenerCreateOpt)
		if err != nil {
			return nil, fmt.Errorf("failed to create listener for loadbalancer %s: %v", lbID, err)
		}

		klog.V(2).Infof("Listener %s created for loadbalancer %s", listener.ID, lbID)
	} else {
		// 同一个service更新时，listener内容更新为service最新
		listenerChanged := false
		updateOpts := listeners.UpdateOpts{}

		if svcConf.connLimit != listener.ConnLimit {
			updateOpts.ConnLimit = &svcConf.connLimit
			listenerChanged = true
		}

		listenerKeepClientIP := listener.InsertHeaders[annotationXForwardedFor] == "true"
		if svcConf.keepClientIP != listenerKeepClientIP {
			updateOpts.InsertHeaders = &listener.InsertHeaders
			if svcConf.keepClientIP {
				if *updateOpts.InsertHeaders == nil {
					*updateOpts.InsertHeaders = make(map[string]string)
				}
				(*updateOpts.InsertHeaders)[annotationXForwardedFor] = "true"
			} else {
				delete(*updateOpts.InsertHeaders, annotationXForwardedFor)
			}
			listenerChanged = true
		}
		if svcConf.tlsContainerRef != listener.DefaultTlsContainerRef {
			updateOpts.DefaultTlsContainerRef = &svcConf.tlsContainerRef
			listenerChanged = true
		}
		if openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureTimeout, lbaas.opts.LBProvider) {
			if svcConf.timeoutClientData != listener.TimeoutClientData {
				updateOpts.TimeoutClientData = &svcConf.timeoutClientData
				listenerChanged = true
			}
			if svcConf.timeoutMemberConnect != listener.TimeoutMemberConnect {
				updateOpts.TimeoutMemberConnect = &svcConf.timeoutMemberConnect
				listenerChanged = true
			}
			if svcConf.timeoutMemberData != listener.TimeoutMemberData {
				updateOpts.TimeoutMemberData = &svcConf.timeoutMemberData
				listenerChanged = true
			}
			if svcConf.timeoutTCPInspect != listener.TimeoutTCPInspect {
				updateOpts.TimeoutTCPInspect = &svcConf.timeoutTCPInspect
				listenerChanged = true
			}
		}
		if openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureVIPACL, lbaas.opts.LBProvider) {
			if !cpoutil.StringListEqual(svcConf.allowedCIDR, listener.AllowedCIDRs) {
				updateOpts.AllowedCIDRs = &svcConf.allowedCIDR
				listenerChanged = true
			}
		}

		if listenerChanged {
			klog.InfoS("Updating listener", "listenerID", listener.ID, "lbID", lbID, "updateOpts", updateOpts)
			if err := openstackutil.UpdateListener(lbaas.lb, lbID, listener.ID, updateOpts); err != nil {
				return nil, fmt.Errorf("failed to update listener %s of loadbalancer %s: %v", listener.ID, lbID, err)
			}
			klog.InfoS("Updated listener", "listenerID", listener.ID, "lbID", lbID)
		}
	}

	return listener, nil
}

// buildListenerCreateOpt returns listeners.CreateOpts for a specific Service port and configuration
func (lbaas *LbaasV2) buildListenerCreateOpt(port corev1.ServicePort, svcConf *serviceConfig, name string) listeners.CreateOpts {
	listenerCreateOpt := listeners.CreateOpts{
		Name:         name,
		Protocol:     listeners.Protocol(port.Protocol),
		ProtocolPort: int(port.Port),
		ConnLimit:    &svcConf.connLimit,
	}
	// 此处改为自定义的tag,将openstack与容器区分开,暂时定义改为name,其中name为listener_portIndex_lbname
	// cpoutil.Sprintf255(lbFormat, servicePrefix, clusterName, service.Namespace, service.Name)
	if svcConf.supportLBTags {
		listenerCreateOpt.Tags = []string{svcConf.lbName}
	}

	if openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureTimeout, lbaas.opts.LBProvider) {
		listenerCreateOpt.TimeoutClientData = &svcConf.timeoutClientData
		listenerCreateOpt.TimeoutMemberConnect = &svcConf.timeoutMemberConnect
		listenerCreateOpt.TimeoutMemberData = &svcConf.timeoutMemberData
		listenerCreateOpt.TimeoutTCPInspect = &svcConf.timeoutTCPInspect
	}

	if svcConf.keepClientIP {
		listenerCreateOpt.InsertHeaders = map[string]string{annotationXForwardedFor: "true"}
	}

	if svcConf.tlsContainerRef != "" {
		listenerCreateOpt.DefaultTlsContainerRef = svcConf.tlsContainerRef
	}

	// protocol selection
	if svcConf.tlsContainerRef != "" && listenerCreateOpt.Protocol != listeners.ProtocolTerminatedHTTPS {
		klog.V(4).Infof("Forcing to use %q protocol for listener because %q annotation is set", listeners.ProtocolTerminatedHTTPS, ServiceAnnotationTlsContainerRef)
		listenerCreateOpt.Protocol = listeners.ProtocolTerminatedHTTPS
	} else if svcConf.keepClientIP && listenerCreateOpt.Protocol != listeners.ProtocolHTTP {
		klog.V(4).Infof("Forcing to use %q protocol for listener because %q annotation is set", listeners.ProtocolHTTP, ServiceAnnotationLoadBalancerXForwardedFor)
		listenerCreateOpt.Protocol = listeners.ProtocolHTTP
	}

	if openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureVIPACL, lbaas.opts.LBProvider) {
		if len(svcConf.allowedCIDR) > 0 {
			listenerCreateOpt.AllowedCIDRs = svcConf.allowedCIDR
		}
	}
	return listenerCreateOpt
}

// getMemberSubnetID gets the configured member-subnet-id from the different possible sources.
func (lbaas *LbaasV2) getMemberSubnetID(service *corev1.Service, svcConf *serviceConfig) (string, error) {
	// Get Member Subnet from Service Annotation
	memberSubnetIDAnnotation := getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerMemberSubnetID, "")
	if memberSubnetIDAnnotation != "" {
		return memberSubnetIDAnnotation, nil
	}

	// Get Member Subnet from Config Class
	configClassName := getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerClass, "")
	if configClassName != "" {
		lbClass := lbaas.opts.LBClasses[configClassName]
		if lbClass == nil {
			return "", fmt.Errorf("invalid loadbalancer class %q", configClassName)
		}
		if lbClass.MemberSubnetID != "" {
			return lbClass.MemberSubnetID, nil
		}
	}

	// Get Member Subnet from Default Config
	if lbaas.opts.MemberSubnetID != "" {
		return lbaas.opts.MemberSubnetID, nil
	}

	return "", nil
}

// getMemberSubnetID gets the configured member-subnet-id from the different possible sources.
func (lbaas *LbaasV2) getMemberSubnetIDByNS(namespace *corev1.Namespace, svcConf *serviceConfig) (string, error) {
	// Get Member Subnet from Service Annotation
	memberSubnetIDAnnotation := getNamespaceFromServiceAnnotation(namespace, NamespaceAnnotationLoadBalancerMemberSubnetID, lbaas.opts.MemberSubnetID)
	if memberSubnetIDAnnotation != "" {
		return memberSubnetIDAnnotation, nil
	}

	return "", nil
}

// getSubnetID gets the configured subnet-id from the different possible sources.
func (lbaas *LbaasV2) getSubnetID(service *corev1.Service, svcConf *serviceConfig) (string, error) {
	// Get subnet from service annotation
	SubnetIDAnnotation := getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerSubnetID, "")
	if SubnetIDAnnotation != "" {
		return SubnetIDAnnotation, nil
	}

	// Get subnet from config class
	configClassName := getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerClass, "")
	if configClassName != "" {
		lbClass := lbaas.opts.LBClasses[configClassName]
		if lbClass == nil {
			return "", fmt.Errorf("invalid loadbalancer class %q", configClassName)
		}
		if lbClass.SubnetID != "" {
			return lbClass.SubnetID, nil
		}
	}

	// Get subnet from Default Config
	if lbaas.opts.SubnetID != "" {
		return lbaas.opts.SubnetID, nil
	}

	return "", nil
}

// getNetworkID gets the configured network-id from the different possible sources.
func (lbaas *LbaasV2) getNetworkID(service *corev1.Service, svcConf *serviceConfig) (string, error) {
	// Get subnet from service annotation
	SubnetIDAnnotation := getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerNetworkID, "")
	if SubnetIDAnnotation != "" {
		return SubnetIDAnnotation, nil
	}

	// Get subnet from config class
	configClassName := getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerClass, "")
	if configClassName != "" {
		lbClass := lbaas.opts.LBClasses[configClassName]
		if lbClass == nil {
			return "", fmt.Errorf("invalid loadbalancer class %q", configClassName)
		}
		if lbClass.NetworkID != "" {
			return lbClass.NetworkID, nil
		}
	}

	// Get subnet from Default Config
	if lbaas.opts.NetworkID != "" {
		return lbaas.opts.NetworkID, nil
	}

	return "", nil
}

func (lbaas *LbaasV2) checkServiceUpdate(service *corev1.Service, nodes []*corev1.Node, svcConf *serviceConfig) error {
	if len(service.Spec.Ports) == 0 {
		return fmt.Errorf("no ports provided to openstack load balancer")
	}
	// serviceName := fmt.Sprintf("%s/%s", service.Namespace, service.Name)

	// 改为从loadbalance获取
	/*if len(service.Spec.IPFamilies) > 0 {
		// Since OCCM does not support multiple load-balancers per service yet,
		// the first IP family will determine the IP family of the load-balancer
		svcConf.preferredIPFamily = service.Spec.IPFamilies[0]
	}*/

	svcConf.lbID = getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerID, "")
	svcConf.supportLBTags = openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureTags, lbaas.opts.LBProvider)

	namespace, err := lbaas.kclient.CoreV1().Namespaces().Get(context.TODO(), service.Namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("checkServiceUpdate: get namespace:%s err:%v", service.Namespace, err.Error())
	}

	// TODO 改成默认从configmap获取默认的memberSubnetID
	svcConf.lbMemberSubnetID, err = lbaas.getMemberSubnetIDByNS(namespace, svcConf)
	if err != nil {
		return fmt.Errorf("unable to get member-subnet-id, %w", err)
	}

	// This affects the protocol of listener and pool
	keepClientIP := getBoolFromServiceAnnotation(service, ServiceAnnotationLoadBalancerXForwardedFor, false)
	useProxyProtocol := getBoolFromServiceAnnotation(service, ServiceAnnotationLoadBalancerProxyEnabled, false)
	if useProxyProtocol && keepClientIP {
		return fmt.Errorf("annotation %s and %s cannot be used together", ServiceAnnotationLoadBalancerProxyEnabled, ServiceAnnotationLoadBalancerXForwardedFor)
	}
	svcConf.keepClientIP = keepClientIP
	svcConf.enableProxyProtocol = useProxyProtocol

	svcConf.tlsContainerRef = getStringFromServiceAnnotation(service, ServiceAnnotationTlsContainerRef, lbaas.opts.TlsContainerRef)
	svcConf.enableMonitor = getBoolFromServiceAnnotation(service, ServiceAnnotationLoadBalancerEnableHealthMonitor, lbaas.opts.CreateMonitor)
	if svcConf.enableMonitor && service.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyTypeLocal && service.Spec.HealthCheckNodePort > 0 {
		svcConf.healthCheckNodePort = int(service.Spec.HealthCheckNodePort)
	}
	svcConf.healthMonitorDelay = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerHealthMonitorDelay, int(lbaas.opts.MonitorDelay.Duration.Seconds()))
	svcConf.healthMonitorTimeout = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerHealthMonitorTimeout, int(lbaas.opts.MonitorTimeout.Duration.Seconds()))
	svcConf.healthMonitorMaxRetries = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerHealthMonitorMaxRetries, int(lbaas.opts.MonitorMaxRetries))
	svcConf.healthMonitorMaxRetriesDown = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerHealthMonitorMaxRetriesDown, int(lbaas.opts.MonitorMaxRetriesDown))
	return nil
}

func (lbaas *LbaasV2) checkServiceDelete(service *corev1.Service, svcConf *serviceConfig, lbID string) error {
	//svcConf.lbID = getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerID, "")
	svcConf.lbID = lbID
	svcConf.supportLBTags = openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureTags, lbaas.opts.LBProvider)

	// This affects the protocol of listener and pool
	svcConf.keepClientIP = getBoolFromServiceAnnotation(service, ServiceAnnotationLoadBalancerXForwardedFor, false)
	svcConf.enableProxyProtocol = getBoolFromServiceAnnotation(service, ServiceAnnotationLoadBalancerProxyEnabled, false)
	svcConf.tlsContainerRef = getStringFromServiceAnnotation(service, ServiceAnnotationTlsContainerRef, lbaas.opts.TlsContainerRef)

	return nil
}

func (lbaas *LbaasV2) checkService(service *corev1.Service, nodes []*corev1.Node, svcConf *serviceConfig, lbID string) (*loadbalancers.LoadBalancer, error) {
	serviceName := fmt.Sprintf("%s/%s", service.Namespace, service.Name)
	var loadbalancer *loadbalancers.LoadBalancer
	supportfip := false
	if len(lbID) == 0 {
		return nil, nil
	}

	ports := service.Spec.Ports
	if len(ports) == 0 {
		return loadbalancer, fmt.Errorf("no service ports provided")
	}

	// 当service为双栈时，ip类型由loadbalance决定（loadbalance只支持单栈）
	// TODO 判断新增/修改模式
	//svcConf.lbID = getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerID, "")
	svcConf.supportLBTags = openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureTags, lbaas.opts.LBProvider)
	if !svcConf.supportLBTags {
		//return loadbalancer, fmt.Errorf("loadbalance not support tags")
	}

	svcConf.internal = true
	svcConf.tlsContainerRef = getStringFromServiceAnnotation(service, ServiceAnnotationTlsContainerRef, lbaas.opts.TlsContainerRef)
	if svcConf.tlsContainerRef != "" {
		if lbaas.secret == nil {
			return loadbalancer, fmt.Errorf("failed to create a TLS Terminated loadbalancer because openstack keymanager client is not "+
				"initialized and default-tls-container-ref %q is set", svcConf.tlsContainerRef)
		}

		// check if container or secret exists for 'barbican' container store
		// tls container ref has the format: https://{keymanager_host}/v1/containers/{uuid} or https://{keymanager_host}/v1/secrets/{uuid}
		if lbaas.opts.ContainerStore == "barbican" {
			slice := strings.Split(svcConf.tlsContainerRef, "/")
			if len(slice) < 2 {
				return loadbalancer, fmt.Errorf("invalid tlsContainerRef for service %s", serviceName)
			}
			barbicanUUID := slice[len(slice)-1]
			barbicanType := slice[len(slice)-2]
			if barbicanType == "containers" {
				container, err := containers.Get(lbaas.secret, barbicanUUID).Extract()
				if err != nil {
					return loadbalancer, fmt.Errorf("failed to get tls container %q: %v", svcConf.tlsContainerRef, err)
				}
				klog.V(4).Infof("Default TLS container %q found", container.ContainerRef)
			} else if barbicanType == "secrets" {
				secret, err := secrets.Get(lbaas.secret, barbicanUUID).Extract()
				if err != nil {
					return loadbalancer, fmt.Errorf("failed to get tls secret %q: %v", svcConf.tlsContainerRef, err)
				}
				klog.V(4).Infof("Default TLS secret %q found", secret.SecretRef)
			} else {
				return loadbalancer, fmt.Errorf("failed to validate tlsContainerRef for service %s: tlsContainerRef type %s unknown", serviceName, barbicanType)
			}
		}
	}

	svcConf.connLimit = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerConnLimit, -1)

	// 此处获取得是fload ip,暂时不用
	lbNetworkID, err := lbaas.getNetworkID(service, svcConf)
	if err != nil {
		return loadbalancer, fmt.Errorf("failed to get network id to create load balancer for service %s: %v", serviceName, err)
	}
	svcConf.lbNetworkID = lbNetworkID

	// TODO 临时留着此货,但增加supportfip 字段跳过此段代码，默认不使用,由CMP传递
	if supportfip == true && len(svcConf.lbNetworkID) == 0 && len(svcConf.lbSubnetID) == 0 {
		subnetID, err := getSubnetIDForLB(lbaas.network, *nodes[0], svcConf.preferredIPFamily)
		if err != nil {
			return loadbalancer, fmt.Errorf("failed to get subnet to create load balancer for service %s: %v", serviceName, err)
		}
		svcConf.lbSubnetID = subnetID
		svcConf.lbMemberSubnetID = subnetID
	}

	loadbalancer, err = openstackutil.GetLoadbalancerByID(lbaas.lb, lbID)
	if err == cpoerrors.ErrNotFound {
		return loadbalancer, fmt.Errorf("load balancer %s is not exist by lbID", lbID)
	}
	if err != nil {
		return loadbalancer, fmt.Errorf("failed to get load balancer %s: %v", lbID, err)
	}
	if loadbalancer.ProvisioningStatus != activeStatus {
		return loadbalancer, fmt.Errorf("load balancer %s is not ACTIVE, current provisioning status: %s", loadbalancer.ID, loadbalancer.ProvisioningStatus)
	}

	loadbalanceIp := net.ParseIP(loadbalancer.VipAddress)
	if loadbalanceIp.To4() != nil {
		svcConf.preferredIPFamily = corev1.IPv4Protocol
	} else {
		svcConf.preferredIPFamily = corev1.IPv6Protocol
	}

	namespace, err := lbaas.kclient.CoreV1().Namespaces().Get(context.TODO(), service.Namespace, metav1.GetOptions{})
	if err != nil {
		return loadbalancer, fmt.Errorf("checkService: get namespace:%s err:%v", service.Namespace, err.Error())
	}

	// 王玉东改成默认从configmap获取默认的memberSubnetID,以及lbaas.opts.MemberSubnetID
	svcConf.lbMemberSubnetID, err = lbaas.getMemberSubnetIDByNS(namespace, svcConf)
	if err != nil {
		return loadbalancer, fmt.Errorf("unable to get member-subnet-id, %w", err)
	}

	klog.V(4).Infof("Ensure an internal loadbalancer service.")

	keepClientIP := getBoolFromServiceAnnotation(service, ServiceAnnotationLoadBalancerXForwardedFor, false)
	useProxyProtocol := getBoolFromServiceAnnotation(service, ServiceAnnotationLoadBalancerProxyEnabled, false)
	if useProxyProtocol && keepClientIP {
		return loadbalancer, fmt.Errorf("annotation %s and %s cannot be used together", ServiceAnnotationLoadBalancerProxyEnabled, ServiceAnnotationLoadBalancerXForwardedFor)
	}
	svcConf.keepClientIP = keepClientIP
	svcConf.enableProxyProtocol = useProxyProtocol

	if openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureTimeout, lbaas.opts.LBProvider) {
		svcConf.timeoutClientData = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerTimeoutClientData, 50000)
		svcConf.timeoutMemberConnect = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerTimeoutMemberConnect, 5000)
		svcConf.timeoutMemberData = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerTimeoutMemberData, 50000)
		svcConf.timeoutTCPInspect = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerTimeoutTCPInspect, 0)
	}

	sourceRanges, err := GetLoadBalancerSourceRanges(service, svcConf.preferredIPFamily)
	if err != nil {
		return loadbalancer, fmt.Errorf("failed to get source ranges for loadbalancer service %s: %v", serviceName, err)
	}
	if openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureVIPACL, lbaas.opts.LBProvider) {
		klog.V(4).Info("LoadBalancerSourceRanges is suppported")
		svcConf.allowedCIDR = sourceRanges.StringSlice()
	} else if lbaas.opts.LBProvider == "ovn" && lbaas.opts.ManageSecurityGroups {
		klog.V(4).Info("LoadBalancerSourceRanges will be enforced on the SG created and attached to LB members")
		svcConf.allowedCIDR = sourceRanges.StringSlice()
	} else {
		klog.Warning("LoadBalancerSourceRanges are ignored")
	}

	if openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureFlavors, lbaas.opts.LBProvider) {
		svcConf.flavorID = getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerFlavorID, lbaas.opts.FlavorID)
	}

	availabilityZone := getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerAvailabilityZone, lbaas.opts.AvailabilityZone)
	if openstackutil.IsOctaviaFeatureSupported(lbaas.lb, openstackutil.OctaviaFeatureAvailabilityZones, lbaas.opts.LBProvider) {
		svcConf.availabilityZone = availabilityZone
	} else if availabilityZone != "" {
		klog.Warning("LoadBalancer Availability Zones aren't supported. Please, upgrade Octavia API to version 2.14 or later (Ussuri release) to use them")
	}

	svcConf.enableMonitor = getBoolFromServiceAnnotation(service, ServiceAnnotationLoadBalancerEnableHealthMonitor, lbaas.opts.CreateMonitor)
	// TODO 2024年4.30前验证直接使用service target port是否可行
	if svcConf.enableMonitor && service.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyTypeLocal && service.Spec.HealthCheckNodePort > 0 {
		svcConf.healthCheckNodePort = int(service.Spec.HealthCheckNodePort)
	}
	svcConf.healthMonitorDelay = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerHealthMonitorDelay, int(lbaas.opts.MonitorDelay.Duration.Seconds()))
	svcConf.healthMonitorTimeout = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerHealthMonitorTimeout, int(lbaas.opts.MonitorTimeout.Duration.Seconds()))
	svcConf.healthMonitorMaxRetries = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerHealthMonitorMaxRetries, int(lbaas.opts.MonitorMaxRetries))
	svcConf.healthMonitorMaxRetriesDown = getIntFromServiceAnnotation(service, ServiceAnnotationLoadBalancerHealthMonitorMaxRetriesDown, int(lbaas.opts.MonitorMaxRetriesDown))
	return loadbalancer, nil
}

// checkListenerPorts checks if there is conflict for ports.
func (lbaas *LbaasV2) checkListenerPorts(service *corev1.Service, curListenerMapping map[listenerKey]*listeners.Listener, lbName string) error {
	for _, svcPort := range service.Spec.Ports {
		key := listenerKey{Protocol: listeners.Protocol(svcPort.Protocol), Port: int(svcPort.Port)}

		if listener, isPresent := curListenerMapping[key]; isPresent {
			// The listener is used by this Service if LB name is in the tags, or
			// the listener was created by this Service.
			// 存在且tag不属于当前service时，则认为已经存在非当前service的listener（openstack||其他service）,
			//  且只要有一个存在，则整体抛错，不再继续进行
			for _, tag := range listener.Tags{
				if strings.Contains(tag, lbName+"_"){
					fmt.Errorf("conflict: the listener port %d already exists", svcPort.Port)
					return fmt.Errorf("conflict: the listener port %d already exists", svcPort.Port)
				}
			}

		}
	}

	return nil
}
func (lbaas *LbaasV2) getMemeberOptions(svcConf *serviceConfig, endpointSlices []*discoveryv1.EndpointSlice) map[int][]v2pools.BatchUpdateMemberOpts {
	// 存储targetPort:[targetPort,Name,SubnetID,Address]
	// 更新memeber前通过 servicePort:[targetPort]与targetPort:[targetPort,Name,SubnetID,Address]关联，获取并组装member信息
	members := make(map[int][]v2pools.BatchUpdateMemberOpts)
	if len(svcConf.lbMemberSubnetID) == 0 {
		return members
	}
	for _, eps := range endpointSlices {
		// Skip if not lb expect preferredIPFamily
		if string(eps.AddressType) != string(svcConf.preferredIPFamily) {
			continue
		}
		lbaas.getMemeberOptionsFromEps(svcConf, eps, members)
	}
	return members
}
func (lbaas *LbaasV2) getMemeberOptionsFromEps(svcConf *serviceConfig, eps *discoveryv1.EndpointSlice, members map[int][]v2pools.BatchUpdateMemberOpts) {

	for _, port := range eps.Ports {

		for _, endpoint := range eps.Endpoints {
			// Skip if not ready and the user does not want to publish not-ready addresses. Note: we're treating nil as ready
			// to be on the safe side as the EndpointConditions doc states "In most cases consumers should interpret this
			// unknown state (ie nil) as ready".
			if endpoint.Conditions.Ready == nil || (endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready) {
				continue
			}
			if len(endpoint.Addresses) == 0 {
				continue
			}

			for addressIndex, address := range endpoint.Addresses {
				// endpointSliceName + Protocol + port + addressIndex
				// // namespace_endpointSliceName_protocol_port_addressIndex
				memberName := cpoutil.Sprintf255(memeberFormat, eps.Namespace, eps.Name, *port.Protocol, *port.Port, addressIndex)
				member := v2pools.BatchUpdateMemberOpts{
					Address:      address,
					ProtocolPort: int(*port.Port),
					Name:         &memberName,
					SubnetID:     &svcConf.lbMemberSubnetID,
					// TODO 进一步确认是否需要
					Tags:         []string{memberName},
				}
				batchUpdateMemberOpts := members[int(*port.Port)]
				if len(batchUpdateMemberOpts) == 0 {
					batchUpdateMemberOpts = make([]v2pools.BatchUpdateMemberOpts, 0)
				}
				batchUpdateMemberOpts = append(batchUpdateMemberOpts, member)
				members[int(*port.Port)] = batchUpdateMemberOpts
				//memberMap := map[int]v2pools.BatchUpdateMemberOpts{int(*port.Port):member}
				//members = append(members, &memberMap)
				klog.V(1).Infof("members is %v", members)
			}

		}
	}
}

func newServicePatcher(kclient kubernetes.Interface, base *corev1.Service) servicePatcher {
	return servicePatcher{
		kclient: kclient,
		base:    base.DeepCopy(),
		updated: base,
	}
}

// Patch will submit a patch request for the Service unless the updated service
// reference contains the same set of annotations as the base copied during
// servicePatcher initialization.
func (sp *servicePatcher) Patch(ctx context.Context, err error) error {
	if reflect.DeepEqual(sp.base.Annotations, sp.updated.Annotations) {
		return err
	}
	perr := cpoutil.PatchService(ctx, sp.kclient, sp.base, sp.updated)
	return utilerrors.NewAggregate([]error{err, perr})
}

func (lbaas *LbaasV2) updateServiceAnnotations(service *corev1.Service, annotations map[string]string) {
	if service.ObjectMeta.Annotations == nil {
		service.ObjectMeta.Annotations = map[string]string{}
	}
	for key, value := range annotations {
		service.ObjectMeta.Annotations[key] = value
	}
}

// createLoadBalancerStatus creates the loadbalancer status from the different possible sources
func (lbaas *LbaasV2) createLoadBalancerStatus(service *corev1.Service, svcConf *serviceConfig, addr string) *corev1.LoadBalancerStatus {
	status := &corev1.LoadBalancerStatus{}
	// If hostname is explicetly set
	if hostname := getStringFromServiceAnnotation(service, ServiceAnnotationLoadBalancerLoadbalancerHostname, ""); hostname != "" {
		status.Ingress = []corev1.LoadBalancerIngress{{Hostname: hostname}}
		return status
	}
	// If the load balancer is using the PROXY protocol, expose its IP address via
	// the Hostname field to prevent kube-proxy from injecting an iptables bypass.
	// This is a workaround until
	// https://github.com/kubernetes/enhancements/tree/master/keps/sig-network/1860-kube-proxy-IP-node-binding
	// is implemented (maybe in v1.22).
	if svcConf.enableProxyProtocol && lbaas.opts.EnableIngressHostname {
		fakeHostname := fmt.Sprintf("%s.%s", addr, lbaas.opts.IngressHostnameSuffix)
		status.Ingress = []corev1.LoadBalancerIngress{{Hostname: fakeHostname}}
		return status
	}
	// Default to IP
	status.Ingress = []corev1.LoadBalancerIngress{{IP: addr}}
	return status
}

func (lbaas *LbaasV2) ensureOctaviaLoadBalancer(ctx context.Context, clusterName string, service *corev1.Service, nodes []*corev1.Node, endpointSlices []*discoveryv1.EndpointSlice, lbID string) (lbs *corev1.LoadBalancerStatus, err error) {
	svcConf := new(serviceConfig)

	// Update the service annotations(e.g. add loadbalancer.openstack.org/load-balancer-id) in the end if it doesn't exist.
	patcher := newServicePatcher(lbaas.kclient, service)
	defer func() { err = patcher.Patch(ctx, err) }()

	var loadbalancer *loadbalancers.LoadBalancer
	if loadbalancer, err = lbaas.checkService(service, nodes, svcConf, lbID); err != nil {
		return nil, err
	}
	if loadbalancer == nil {
		klog.Info("loadbalancer is nil,lbID:%v", lbID)
		return nil, nil
	}

	svcConf.lbID = lbID

	// Use more meaningful name for the load balancer but still need to check the legacy name for backward compatibility.
	// lbName:k8s_svcNs_svcName
	lbName := lbaas.GetLoadBalancerName(ctx, loadbalancer.Name, service)
	svcConf.lbName = lbName
	//serviceName := fmt.Sprintf("%s/%s", service.Namespace, service.Name)

	loadbalancer.Listeners, err = openstackutil.GetListenersByLoadBalancerID(lbaas.lb, loadbalancer.ID)
	if err != nil {
		return nil, err
	}

	klog.V(4).InfoS("Load balancer ensured", "lbID", loadbalancer.ID)

	// This is an existing load balancer, either created by occm for other Services or by the user outside of cluster, or
	// a newly created, unpopulated loadbalancer that needs populating.
	curListeners := loadbalancer.Listeners
	curListenerMapping := make(map[listenerKey]*listeners.Listener)

	// 查询已经listner
	for i, l := range curListeners {
		key := listenerKey{Protocol: listeners.Protocol(l.Protocol), Port: l.ProtocolPort}
		curListenerMapping[key] = &curListeners[i]
	}
	klog.V(4).InfoS("Existing listeners", "portProtocolMapping", curListenerMapping)

	// Check port conflicts
	// 校验listener port是否已被openstack||其他service占用
	if err := lbaas.checkListenerPorts(service, curListenerMapping, lbName); err != nil {
		return nil, err
	}

	lbmembers := lbaas.getMemeberOptions(svcConf, endpointSlices)
	klog.V(1).Infof("lbmembers is %v", lbmembers)

	// 生成listener+pool+memeber
	for portIndex, port := range service.Spec.Ports {
		listener, err := lbaas.ensureOctaviaListener(loadbalancer.ID, cpoutil.Sprintf255(listenerFormat, lbName, portIndex), curListenerMapping, port, svcConf, service)
		if err != nil {
			return nil, err
		}

		// 包含pool和memeber
		pool, err := lbaas.ensureOctaviaPool(loadbalancer.ID, cpoutil.Sprintf255(poolFormat, lbName, portIndex), listener, service, port, nodes, svcConf, lbmembers)
		if err != nil {
			return nil, err
		}

		if err := lbaas.ensureOctaviaHealthMonitor(loadbalancer.ID, cpoutil.Sprintf255(monitorFormat, portIndex, lbName), pool, port, svcConf); err != nil {
			return nil, err
		}

		// After all ports have been processed, remaining listeners are removed if they were created by this Service.
		// The remove of the listener must always happen at the end of the loop to avoid wrong assignment.
		// Modifying the curListeners would also change the mapping.
		curListeners = popListener(curListeners, listener.ID)
	}

	/*	// TODO 此代码删除，lb由CMP创建，一个lb可对应多个service
			// Deal with the remaining listeners, delete the listener if it was created by this Service previously.
			if err := lbaas.deleteOctaviaListeners(loadbalancer.ID, curListeners, isLBOwner, lbName); err != nil {
				return nil, err
			}
		//}


		// Add annotation to Service and add LB name to load balancer tags.
		annotationUpdate := map[string]string{
			ServiceAnnotationLoadBalancerID:      loadbalancer.ID,
			ServiceAnnotationLoadBalancerAddress: addr,
		}
		lbaas.updateServiceAnnotations(service, annotationUpdate)
		if svcConf.supportLBTags {
			lbTags := loadbalancer.Tags
			if !cpoutil.Contains(lbTags, lbName) {
				lbTags = append(lbTags, lbName)
				klog.InfoS("Updating load balancer tags", "lbID", loadbalancer.ID, "tags", lbTags)
				if err := openstackutil.UpdateLoadBalancerTags(lbaas.lb, loadbalancer.ID, lbTags); err != nil {
					return nil, err
				}
			}
		}

		// 王玉东remove old loadblance id
		// Create status the load balancer*/

	//patcher := newServicePatcher(lbaas.kclient, service)
	status := &corev1.LoadBalancerStatus{}
	status.Ingress = []corev1.LoadBalancerIngress{{IP: loadbalancer.VipAddress}}
	//status := lbaas.createLoadBalancerStatus(service, svcConf, addr)

	if lbaas.opts.ManageSecurityGroups {
		err := lbaas.ensureAndUpdateOctaviaSecurityGroup(clusterName, service, nodes, svcConf)
		if err != nil {
			return status, fmt.Errorf("failed when reconciling security groups for LB service %v/%v: %v", service.Namespace, service.Name, err)
		}
	} else {
		// Attempt to delete the SG if `manage-security-groups` is disabled. When CPO is reconfigured to enable it we
		// will reconcile the LB and create the SG. This is to make sure it works the same in the opposite direction.
		if err := lbaas.EnsureSecurityGroupDeleted(clusterName, service); err != nil {
			return status, err
		}
	}

	return status, nil
}

// EnsureLoadBalancer creates a new load balancer or updates the existing one.
func (lbaas *LbaasV2) EnsureLoadBalancer(ctx context.Context, clusterName string, apiService *corev1.Service, nodes []*corev1.Node, endpointSlices []*discoveryv1.EndpointSlice, lbId string) (*corev1.LoadBalancerStatus, error) {
	mc := metrics.NewMetricContext("loadbalancer", "ensure")
	klog.InfoS("EnsureLoadBalancer", "cluster", clusterName, "service", klog.KObj(apiService))

	status, err := lbaas.ensureOctaviaLoadBalancer(ctx, clusterName, apiService, nodes, endpointSlices, lbId)

	return status, mc.ObserveReconcile(err)
}

func (lbaas *LbaasV2) listSubnetsForNetwork(networkID string, tweak ...TweakSubNetListOpsFunction) ([]subnets.Subnet, error) {
	var opts = subnets.ListOpts{NetworkID: networkID}
	for _, f := range tweak {
		if f != nil {
			f(&opts)
		}
	}
	mc := metrics.NewMetricContext("subnet", "list")
	allPages, err := subnets.List(lbaas.network, opts).AllPages()
	if mc.ObserveRequest(err) != nil {
		return nil, fmt.Errorf("error listing subnets of network %s: %v", networkID, err)
	}
	subs, err := subnets.ExtractSubnets(allPages)
	if err != nil {
		return nil, fmt.Errorf("error extracting subnets from pages: %v", err)
	}

	if len(subs) == 0 {
		return nil, fmt.Errorf("could not find subnets for network %s", networkID)
	}
	return subs, nil
}

// group, if it not present.
func (lbaas *LbaasV2) ensureSecurityRule(sgRuleCreateOpts rules.CreateOpts) error {
	mc := metrics.NewMetricContext("security_group_rule", "create")
	_, err := rules.Create(lbaas.network, sgRuleCreateOpts).Extract()
	if err != nil && cpoerrors.IsConflictError(err) {
		// Conflict means the SG rule already exists, so ignoring that error.
		klog.Warningf("Security group rule already found when trying to create it. This indicates concurrent "+
			"updates to the SG %s and is unexpected", sgRuleCreateOpts.SecGroupID)
		return mc.ObserveRequest(nil)
	} else if mc.ObserveRequest(err) != nil {
		return fmt.Errorf("failed to create rule for security group %s: %v", sgRuleCreateOpts.SecGroupID, err)
	}
	return nil
}

func (lbaas *LbaasV2) updateOctaviaLoadBalancer(ctx context.Context, clusterName string, service *corev1.Service, nodes []*corev1.Node) error {
	svcConf := new(serviceConfig)
	var err error
	if err := lbaas.checkServiceUpdate(service, nodes, svcConf); err != nil {
		return err
	}

	serviceName := fmt.Sprintf("%s/%s", service.Namespace, service.Name)
	klog.V(2).Infof("Updating %d nodes for Service %s in cluster %s", len(nodes), serviceName, clusterName)

	// Get load balancer
	var loadbalancer *loadbalancers.LoadBalancer
	if svcConf.lbID != "" {
		loadbalancer, err = openstackutil.GetLoadbalancerByID(lbaas.lb, svcConf.lbID)
		if err != nil {
			return fmt.Errorf("failed to get load balancer %s: %v", svcConf.lbID, err)
		}
	} else {
		// This is a Service created before shared LB is supported.
		name := lbaas.GetLoadBalancerName(ctx, clusterName, service)
		legacyName := lbaas.getLoadBalancerLegacyName(ctx, clusterName, service)
		loadbalancer, err = getLoadbalancerByName(lbaas.lb, name, legacyName)
		if err != nil {
			return err
		}
	}
	if loadbalancer.ProvisioningStatus != activeStatus {
		return fmt.Errorf("load balancer %s is not ACTIVE, current provisioning status: %s", loadbalancer.ID, loadbalancer.ProvisioningStatus)
	}

	loadbalancer.Listeners, err = openstackutil.GetListenersByLoadBalancerID(lbaas.lb, loadbalancer.ID)
	if err != nil {
		return err
	}

	// Now, we have a load balancer.
	lbName := lbaas.GetLoadBalancerName(ctx, loadbalancer.Name, service)
	// Get all listeners for this loadbalancer, by "port&protocol".
	lbListeners := make(map[listenerKey]listeners.Listener)
	for _, l := range loadbalancer.Listeners {
		key := listenerKey{Protocol: listeners.Protocol(l.Protocol), Port: l.ProtocolPort}
		lbListeners[key] = l
	}

	// Update pool members for each listener.
	for portIndex, port := range service.Spec.Ports {
		proto := getListenerProtocol(port.Protocol, svcConf)
		listener, ok := lbListeners[listenerKey{
			Protocol: proto,
			Port:     int(port.Port),
		}]
		if !ok {
			return fmt.Errorf("loadbalancer %s does not contain required listener for port %d and protocol %s", loadbalancer.ID, port.Port, port.Protocol)
		}

		pool, err := lbaas.ensureOctaviaPool(loadbalancer.ID, cpoutil.Sprintf255(poolFormat, lbName, portIndex), &listener, service, port, nodes, svcConf, nil)
		if err != nil {
			return err
		}

		err = lbaas.ensureOctaviaHealthMonitor(loadbalancer.ID, cpoutil.Sprintf255(monitorFormat, portIndex, loadbalancer.Name), pool, port, svcConf)
		if err != nil {
			return err
		}
	}

	if lbaas.opts.ManageSecurityGroups {
		err := lbaas.ensureAndUpdateOctaviaSecurityGroup(clusterName, service, nodes, svcConf)
		if err != nil {
			return fmt.Errorf("failed to update Security Group for loadbalancer service %s: %v", serviceName, err)
		}
	}
	// We don't try to lookup and delete the SG here when `manage-security-group=false` as `UpdateLoadBalancer()` is
	// only called on changes to the list of the Nodes. Deletion of the SG on reconfiguration will be handled by
	// EnsureLoadBalancer() that is the true LB reconcile function.

	return nil
}

// UpdateLoadBalancer updates hosts under the specified load balancer.
func (lbaas *LbaasV2) UpdateLoadBalancer(ctx context.Context, clusterName string, service *corev1.Service, nodes []*corev1.Node) error {
	mc := metrics.NewMetricContext("loadbalancer", "update")
	err := lbaas.updateOctaviaLoadBalancer(ctx, clusterName, service, nodes)
	return mc.ObserveReconcile(err)
}

func compareSecurityGroupRuleAndCreateOpts(rule rules.SecGroupRule, opts rules.CreateOpts) bool {
	return rule.Direction == string(opts.Direction) &&
		strings.EqualFold(rule.Protocol, string(opts.Protocol)) &&
		rule.EtherType == string(opts.EtherType) &&
		rule.RemoteIPPrefix == opts.RemoteIPPrefix &&
		rule.PortRangeMin == opts.PortRangeMin &&
		rule.PortRangeMax == opts.PortRangeMax
}

func getRulesToCreateAndDelete(wantedRules []rules.CreateOpts, existingRules []rules.SecGroupRule) ([]rules.CreateOpts, []rules.SecGroupRule) {
	toCreate := make([]rules.CreateOpts, 0, len(wantedRules))     // Max is all rules need creation
	toDelete := make([]rules.SecGroupRule, 0, len(existingRules)) // Max will be all the existing rules to be deleted
	// Surely this can be done in a more efficient way. Is it worth optimizing if most of
	// the time we'll deal with just 1 or 2 elements in each array? I doubt it.
	for _, existingRule := range existingRules {
		found := false
		for _, wantedRule := range wantedRules {
			if compareSecurityGroupRuleAndCreateOpts(existingRule, wantedRule) {
				found = true
				break
			}
		}
		if !found {
			// in existingRules but not in wantedRules, delete
			toDelete = append(toDelete, existingRule)
		}
	}
	for _, wantedRule := range wantedRules {
		found := false
		for _, existingRule := range existingRules {
			if compareSecurityGroupRuleAndCreateOpts(existingRule, wantedRule) {
				found = true
				break
			}
		}
		if !found {
			// in wantedRules but not in exisitngRules, create
			toCreate = append(toCreate, wantedRule)
		}
	}

	return toCreate, toDelete
}

// ensureAndUpdateOctaviaSecurityGroup handles the creation and update of the security group and the securiry rules for the octavia load balancer
func (lbaas *LbaasV2) ensureAndUpdateOctaviaSecurityGroup(clusterName string, apiService *corev1.Service, nodes []*corev1.Node, svcConf *serviceConfig) error {
	// get service ports
	ports := apiService.Spec.Ports
	if len(ports) == 0 {
		return fmt.Errorf("no ports provided to openstack load balancer")
	}

	// ensure security group for LB
	lbSecGroupName := getSecurityGroupName(apiService)
	lbSecGroupID, err := secgroups.IDFromName(lbaas.network, lbSecGroupName)
	if err != nil {
		// If the security group of LB not exist, create it later
		if cpoerrors.IsNotFound(err) {
			lbSecGroupID = ""
		} else {
			return fmt.Errorf("error occurred finding security group: %s: %v", lbSecGroupName, err)
		}
	}
	if len(lbSecGroupID) == 0 {
		// create security group
		lbSecGroupCreateOpts := groups.CreateOpts{
			Name:        lbSecGroupName,
			Description: fmt.Sprintf("Security Group for %s/%s Service LoadBalancer in cluster %s", apiService.Namespace, apiService.Name, clusterName),
		}

		mc := metrics.NewMetricContext("security_group", "create")
		lbSecGroup, err := groups.Create(lbaas.network, lbSecGroupCreateOpts).Extract()
		if mc.ObserveRequest(err) != nil {
			return fmt.Errorf("failed to create Security Group for loadbalancer service %s/%s: %v", apiService.Namespace, apiService.Name, err)
		}
		lbSecGroupID = lbSecGroup.ID
	}

	mc := metrics.NewMetricContext("subnet", "get")
	subnet, err := subnets.Get(lbaas.network, svcConf.lbMemberSubnetID).Extract()
	if mc.ObserveRequest(err) != nil {
		return fmt.Errorf(
			"failed to find subnet %s from openstack: %v", svcConf.lbMemberSubnetID, err)
	}

	etherType := rules.EtherType4
	if netutils.IsIPv6CIDRString(subnet.CIDR) {
		etherType = rules.EtherType6
	}
	cidrs := []string{subnet.CIDR}
	if lbaas.opts.LBProvider == "ovn" {
		// OVN keeps the source IP of the incoming traffic. This means that we cannot just open the LB range, but we
		// need to open for the whole world. This can be restricted by using the service.spec.loadBalancerSourceRanges.
		// svcConf.allowedCIDR will give us the ranges calculated by GetLoadBalancerSourceRanges() earlier.
		cidrs = svcConf.allowedCIDR
	}

	existingRules, err := getSecurityGroupRules(lbaas.network, rules.ListOpts{SecGroupID: lbSecGroupID})
	if err != nil {
		return fmt.Errorf(
			"failed to find security group rules in %s: %v", lbSecGroupID, err)
	}

	// List of the security group rules wanted in the SG.
	// Number of Ports plus the potential HealthCheckNodePort.
	wantedRules := make([]rules.CreateOpts, 0, len(ports)+1)

	if apiService.Spec.HealthCheckNodePort != 0 {
		// TODO(dulek): How should this work with OVN…? Do we need to allow all?
		//              Probably the traffic goes from the compute node?
		wantedRules = append(wantedRules,
			rules.CreateOpts{
				Direction:      rules.DirIngress,
				Protocol:       rules.ProtocolTCP,
				EtherType:      etherType,
				RemoteIPPrefix: subnet.CIDR,
				SecGroupID:     lbSecGroupID,
				PortRangeMin:   int(apiService.Spec.HealthCheckNodePort),
				PortRangeMax:   int(apiService.Spec.HealthCheckNodePort),
			},
		)
	}

	for _, port := range ports {
		if port.NodePort == 0 { // It's 0 when AllocateLoadBalancerNodePorts=False
			continue
		}
		for _, cidr := range cidrs {
			protocol := strings.ToLower(string(port.Protocol)) // K8s uses TCP, Neutron uses tcp, etc.
			wantedRules = append(wantedRules,
				rules.CreateOpts{
					Direction:      rules.DirIngress,
					Protocol:       rules.RuleProtocol(protocol),
					EtherType:      etherType,
					RemoteIPPrefix: cidr,
					SecGroupID:     lbSecGroupID,
					PortRangeMin:   int(port.NodePort),
					PortRangeMax:   int(port.NodePort),
				},
			)
		}
	}

	toCreate, toDelete := getRulesToCreateAndDelete(wantedRules, existingRules)

	// create new rules
	for _, opts := range toCreate {
		err := lbaas.ensureSecurityRule(opts)
		if err != nil {
			return fmt.Errorf("failed to apply security rule (%v), %w", opts, err)
		}
	}

	// delete unneeded rules
	for _, existingRule := range toDelete {
		klog.Infof("Deleting rule %s from security group %s (%s)", existingRule.ID, existingRule.SecGroupID, lbSecGroupName)
		mc := metrics.NewMetricContext("security_group_rule", "delete")
		err := rules.Delete(lbaas.network, existingRule.ID).ExtractErr()
		if err != nil && cpoerrors.IsNotFound(err) {
			// ignore 404
			klog.Warningf("Security group rule %s found missing when trying to delete it. This indicates concurrent "+
				"updates to the SG %s and is unexpected", existingRule.ID, existingRule.SecGroupID)
			return mc.ObserveRequest(nil)
		} else if mc.ObserveRequest(err) != nil {
			return fmt.Errorf("failed to delete security group rule %s: %w", existingRule.ID, err)
		}
	}

	if err := applyNodeSecurityGroupIDForLB(lbaas.network, svcConf, nodes, lbSecGroupID); err != nil {
		return err
	}
	return nil
}

// EnsureLoadBalancerDeleted deletes the specified load balancer
func (lbaas *LbaasV2) EnsureLoadBalancerDeleted(ctx context.Context, clusterName string, service *corev1.Service, lbId string) error {
	mc := metrics.NewMetricContext("loadbalancer", "delete")
	err := lbaas.ensureLoadBalancerDeleted(ctx, clusterName, service, lbId)
	return mc.ObserveReconcile(err)
}

func (lbaas *LbaasV2) deleteFIPIfCreatedByProvider(fip *floatingips.FloatingIP, portID string, service *corev1.Service) (bool, error) {
	matched, err := regexp.Match("Floating IP for Kubernetes external service", []byte(fip.Description))
	if err != nil {
		return false, err
	}

	if !matched {
		// It's not a FIP created by us, don't touch it.
		return false, nil
	}
	klog.InfoS("Deleting floating IP for service", "floatingIP", fip.FloatingIP, "service", klog.KObj(service))
	mc := metrics.NewMetricContext("floating_ip", "delete")
	err = floatingips.Delete(lbaas.network, fip.ID).ExtractErr()
	if mc.ObserveRequest(err) != nil {
		return false, fmt.Errorf("failed to delete floating IP %s for loadbalancer VIP port %s: %v", fip.FloatingIP, portID, err)
	}
	klog.InfoS("Deleted floating IP for service", "floatingIP", fip.FloatingIP, "service", klog.KObj(service))
	return true, nil
}

// handle service delete && remove loadbalanceId ,add oldloadbalanceId
func (lbaas *LbaasV2) ensureLoadBalancerDeleted(ctx context.Context, clusterName string, service *corev1.Service, lbID string) error {
	klog.V(1).Infof("begin to delete LoadBalancer service: %v, lbID: %v", service, lbID)

	if service.Status.Size() == 0 || service.Status.LoadBalancer.Size() == 0{
		klog.V(1).Infof("service not bond to lb" )
		return nil
	}
	lbName := lbaas.GetLoadBalancerName(ctx, clusterName, service)
	// loadbalance由CMP创建，serivce和lb只能通过serivce的注解关联上
	//legacyName := lbaas.getLoadBalancerLegacyName(ctx, clusterName, service)
	var err error
	var loadbalancer *loadbalancers.LoadBalancer
	// TODO LB默认为share,且provider-openstack不处理LB

	// 没有lbID默认不再处理
	if len(lbID) == 0 {
		return nil
	}

	svcConf := new(serviceConfig)
	if err := lbaas.checkServiceDelete(service, svcConf, lbID); err != nil {
		return err
	}

	loadbalancer, err = openstackutil.GetLoadbalancerByID(lbaas.lb, svcConf.lbID)
	klog.V(1).Infof("deleting LoadBalancer loadbalancer: %v", loadbalancer)
	if err == cpoerrors.ErrNotFound {
		//return fmt.Errorf("load balancer %s is not exist by lbID", svcConf.lbID)
		// load balancer不存在时，默认已被删除
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get load balancer %s: %v", svcConf.lbID, err)
	}
	if loadbalancer.ProvisioningStatus != activeStatus {
		return fmt.Errorf("load balancer %s is not ACTIVE, current provisioning status: %s", loadbalancer.ID, loadbalancer.ProvisioningStatus)
	}
	if loadbalancer.ProvisioningStatus != activeStatus && loadbalancer.ProvisioningStatus != errorStatus {
		return fmt.Errorf("load balancer %s is in immutable status, current provisioning status: %s", loadbalancer.ID, loadbalancer.ProvisioningStatus)
	}

	//klog.V(4).InfoS("Deleting service", "service", klog.KObj(service), "needDeleteLB", needDeleteLB, "isSharedLB", isSharedLB, "updateLBTag", updateLBTag, "isCreatedByOCCM", isCreatedByOCCM)

	// get all listeners associated with this loadbalancer
	listenerList, err := openstackutil.GetListenersByLoadBalancerID(lbaas.lb, loadbalancer.ID)
	klog.V(1).Infof("deleting LoadBalancer listenerList is :  %v", listenerList)
	if err != nil {
		return fmt.Errorf("error getting LB %s listeners: %v", loadbalancer.ID, err)
	}

	// TODO 默认不删除LB
	var listenersToDelete []listeners.Listener
	curListenerMapping := make(map[listenerKey]*listeners.Listener)
	for i, l := range listenerList {
		key := listenerKey{Protocol: listeners.Protocol(l.Protocol), Port: l.ProtocolPort}
		curListenerMapping[key] = &listenerList[i]
	}

	for _, port := range service.Spec.Ports {
		proto := getListenerProtocol(port.Protocol, svcConf)
		listener, isPresent := curListenerMapping[listenerKey{
			Protocol: proto,
			Port:     int(port.Port),
		}]
		// 这一部分不需要改，通过listener的tags以及key确认listener的归属
		klog.V(1).Infof("listener.Tags:  %v, lbName: %v", listener.Tags, lbName)
		if isPresent && strings.Contains(listener.Name, lbName+"_"){
			listenersToDelete = append(listenersToDelete, *listener)
		}
	}
	klog.V(1).Infof("listenersToDelete:  %v", listenersToDelete)
	listenerList = listenersToDelete

	// get all pools (and health monitors) associated with this loadbalancer
	var monitorIDs []string
	for _, listener := range listenerList {
		pool, err := openstackutil.GetPoolByListener(lbaas.lb, loadbalancer.ID, listener.ID)
		if err != nil && err != cpoerrors.ErrNotFound {
			return fmt.Errorf("error getting pool for listener %s: %v", listener.ID, err)
		}

		if pool != nil {
			if pool.MonitorID != "" {
				monitorIDs = append(monitorIDs, pool.MonitorID)
			}
		}
	}

	// delete monitors
	for _, monitorID := range monitorIDs {
		klog.InfoS("Deleting health monitor", "monitorID", monitorID, "lbID", loadbalancer.ID)
		if err := openstackutil.DeleteHealthMonitor(lbaas.lb, monitorID, loadbalancer.ID); err != nil {
			return err
		}
		klog.InfoS("Deleted health monitor", "monitorID", monitorID, "lbID", loadbalancer.ID)
	}

	// delete listeners
	if err := lbaas.deleteListeners(loadbalancer.ID, listenerList); err != nil {
		return err
	}

	// 暂不需要处理
	// Delete the Security Group. We're doing that even if `manage-security-groups` is disabled to make sure we don't
	// orphan created SGs even if CPO got reconfigured.
	if err := lbaas.EnsureSecurityGroupDeleted(clusterName, service); err != nil {
		return err
	}

	return nil
}

// EnsureSecurityGroupDeleted deleting security group for specific loadbalancer service.
func (lbaas *LbaasV2) EnsureSecurityGroupDeleted(_ string, service *corev1.Service) error {
	// Generate Name
	lbSecGroupName := getSecurityGroupName(service)
	lbSecGroupID, err := secgroups.IDFromName(lbaas.network, lbSecGroupName)
	if err != nil {
		if cpoerrors.IsNotFound(err) {
			// It is OK when the security group has been deleted by others.
			return nil
		}
		return fmt.Errorf("error occurred finding security group: %s: %v", lbSecGroupName, err)
	}

	// Disassociate the security group from the neutron ports on the nodes.
	if err := disassociateSecurityGroupForLB(lbaas.network, lbSecGroupID); err != nil {
		return fmt.Errorf("failed to disassociate security group %s: %v", lbSecGroupID, err)
	}

	mc := metrics.NewMetricContext("security_group", "delete")
	lbSecGroup := groups.Delete(lbaas.network, lbSecGroupID)
	if lbSecGroup.Err != nil && !cpoerrors.IsNotFound(lbSecGroup.Err) {
		return mc.ObserveRequest(lbSecGroup.Err)
	}
	_ = mc.ObserveRequest(nil)

	return nil
}

// GetLoadBalancerSourceRanges first try to parse and verify LoadBalancerSourceRanges field from a service.
// If the field is not specified, turn to parse and verify the AnnotationLoadBalancerSourceRangesKey annotation from a service,
// extracting the source ranges to allow, and if not present returns a default (allow-all) value.
func GetLoadBalancerSourceRanges(service *corev1.Service, preferredIPFamily corev1.IPFamily) (netsets.IPNet, error) {
	var ipnets netsets.IPNet
	var err error
	// if SourceRange field is specified, ignore sourceRange annotation
	if len(service.Spec.LoadBalancerSourceRanges) > 0 {
		specs := service.Spec.LoadBalancerSourceRanges
		ipnets, err = netsets.ParseIPNets(specs...)

		if err != nil {
			return nil, fmt.Errorf("service.Spec.LoadBalancerSourceRanges: %v is not valid. Expecting a list of IP ranges. For example, 10.0.0.0/24. Error msg: %v", specs, err)
		}
	} else {
		val := service.Annotations[corev1.AnnotationLoadBalancerSourceRangesKey]
		val = strings.TrimSpace(val)
		if val == "" {
			if preferredIPFamily == corev1.IPv6Protocol {
				val = defaultLoadBalancerSourceRangesIPv6
			} else {
				val = defaultLoadBalancerSourceRangesIPv4
			}
		}
		specs := strings.Split(val, ",")
		ipnets, err = netsets.ParseIPNets(specs...)
		if err != nil {
			return nil, fmt.Errorf("%s: %s is not valid. Expecting a comma-separated list of source IP ranges. For example, 10.0.0.0/24,192.168.2.0/24", corev1.AnnotationLoadBalancerSourceRangesKey, val)
		}
	}
	return ipnets, nil
}

// PreserveGopherError preserves the error details delivered with the response
// that are explicitly discarded by dedicated error types.
// The gopher library, because of an unknown reason, explicitly hides
// the detailed error information from the response body and replaces it
// with a generic phrase that does not help to identify the problem anymore.
// This method resurrects the error message from the response body for
// such cases. For example for an 404 Error the provided message just
// tells `Resource not found`, which is not helpful, because it hides
// the real error information, which might be something completely different.
// error types from provider_client.go
func PreserveGopherError(rawError error) error {
	if rawError == nil {
		return nil
	}
	if v, ok := rawError.(gophercloud.ErrErrorAfterReauthentication); ok {
		rawError = v.ErrOriginal
	}
	var details []byte
	switch e := rawError.(type) {
	case gophercloud.ErrDefault400:
	case gophercloud.ErrDefault401:
		details = e.Body
	case gophercloud.ErrDefault403:
	case gophercloud.ErrDefault404:
		details = e.Body
	case gophercloud.ErrDefault405:
		details = e.Body
	case gophercloud.ErrDefault408:
		details = e.Body
	case gophercloud.ErrDefault409:
	case gophercloud.ErrDefault429:
		details = e.Body
	case gophercloud.ErrDefault500:
		details = e.Body
	case gophercloud.ErrDefault503:
		details = e.Body
	default:
		return rawError
	}

	if details != nil {
		return fmt.Errorf("%s: %s", rawError, details)
	}
	return rawError
}

// getStringFromServiceAnnotation searches a given v1.Service for a specific annotationKey and either returns the annotation's value or a specified defaultSetting
func getStringFromServiceAnnotation(service *corev1.Service, annotationKey string, defaultSetting string) string {
	klog.V(4).Infof("getStringFromServiceAnnotation(%s/%s, %v, %v)", service.Namespace, service.Name, annotationKey, defaultSetting)
	if annotationValue, ok := service.Annotations[annotationKey]; ok {
		//if there is an annotation for this setting, set the "setting" var to it
		// annotationValue can be empty, it is working as designed
		// it makes possible for instance provisioning loadbalancer without floatingip
		klog.V(4).Infof("Found a Service Annotation: %v = %v", annotationKey, annotationValue)
		return annotationValue
	}
	//if there is no annotation, set "settings" var to the value from cloud config
	if defaultSetting != "" {
		klog.V(4).Infof("Could not find a Service Annotation; falling back on cloud-config setting: %v = %v", annotationKey, defaultSetting)
	}
	return defaultSetting
}
