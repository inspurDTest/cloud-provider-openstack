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
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	// ServiceAnnotationLoadBalancerIDLegacy is the upstream OCCM annotation key.
	ServiceAnnotationLoadBalancerIDLegacy = "loadbalancer.openstack.org/load-balancer-id"
	serviceCleanupResyncPeriod            = 5 * time.Minute
)

var serviceCleanupStarter sync.Once

type serviceCleanupTask struct {
	namespace string
	name      string
	lbIDs     []string
}

// startServiceCleanupWatcherIfNeeded watches Service updates and cleans up Octavia
// listeners when a Service stops using LoadBalancer (e.g. LoadBalancer -> NodePort).
// This complements the cloud-provider service controller without forking that module.
func (lbaas *LbaasV2) startServiceCleanupWatcherIfNeeded() {
	if lbaas.kclient == nil {
		klog.InfoS("skip service cleanup watcher: kubernetes client is nil")
		return
	}
	serviceCleanupStarter.Do(func() {
		go lbaas.runServiceCleanupWatcher()
	})
}

func (lbaas *LbaasV2) runServiceCleanupWatcher() {
	klog.InfoS("starting OpenStack service cleanup watcher (LoadBalancer type/annotation transitions)")

	stopCh := make(chan struct{})
	informerFactory := informers.NewSharedInformerFactory(lbaas.kclient, serviceCleanupResyncPeriod)
	serviceInformer := informerFactory.Core().V1().Services()

	queue := workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(),
		"openstack-service-lb-cleanup",
	)

	serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldSvc, ok1 := oldObj.(*corev1.Service)
			newSvc, ok2 := newObj.(*corev1.Service)
			if !ok1 || !ok2 {
				return
			}
			if !shouldCleanupOpenStackLBAfterServiceChange(oldSvc, newSvc) {
				return
			}
			lbIDs := collectLbIDsForServiceCleanup(oldSvc, newSvc)
			if len(lbIDs) == 0 {
				klog.InfoS("service cleanup watcher: transition detected but no LB ID on old/new Service",
					"service", klog.KRef(newSvc.Namespace, newSvc.Name),
					"oldType", oldSvc.Spec.Type,
					"newType", newSvc.Spec.Type)
				return
			}
			klog.InfoS("service cleanup watcher: enqueue OpenStack cleanup",
				"service", klog.KRef(newSvc.Namespace, newSvc.Name),
				"oldType", oldSvc.Spec.Type,
				"newType", newSvc.Spec.Type,
				"lbIDs", lbIDs)
			queue.Add(serviceCleanupTask{
				namespace: newSvc.Namespace,
				name:      newSvc.Name,
				lbIDs:     lbIDs,
			})
		},
	})

	informerFactory.Start(stopCh)
	if !cache.WaitForCacheSync(stopCh, serviceInformer.Informer().HasSynced) {
		klog.ErrorS(nil, "service cleanup watcher failed to sync Service informer cache")
		return
	}

	go wait.Until(func() {
		for lbaas.processNextServiceCleanup(queue) {
		}
	}, time.Second, stopCh)

	klog.InfoS("OpenStack service cleanup watcher is running")
	<-stopCh
}

func (lbaas *LbaasV2) processNextServiceCleanup(queue workqueue.RateLimitingInterface) bool {
	obj, shutdown := queue.Get()
	if shutdown {
		return false
	}
	defer queue.Done(obj)

	task, ok := obj.(serviceCleanupTask)
	if !ok {
		queue.Forget(obj)
		return true
	}

	ctx := context.Background()
	svc, err := lbaas.kclient.CoreV1().Services(task.namespace).Get(ctx, task.name, metav1.GetOptions{})
	if err != nil {
		klog.ErrorS(err, "service cleanup watcher: failed to get Service",
			"service", klog.KRef(task.namespace, task.name))
		queue.Forget(obj)
		return true
	}

	clusterID, err := lbaas.clusterIDFromConfigMap(ctx)
	if err != nil {
		klog.ErrorS(err, "service cleanup watcher: failed to resolve cluster ID",
			"service", klog.KRef(task.namespace, task.name))
		queue.AddRateLimited(obj)
		return true
	}

	for _, lbID := range task.lbIDs {
		klog.InfoS("service cleanup watcher: deleting OpenStack LB resources",
			"service", klog.KRef(task.namespace, task.name),
			"serviceType", svc.Spec.Type,
			"lbID", lbID,
			"clusterID", clusterID)
		if err := lbaas.ensureLoadBalancerDeleted(ctx, clusterID, svc, lbID); err != nil {
			klog.ErrorS(err, "service cleanup watcher: ensureLoadBalancerDeleted failed",
				"service", klog.KRef(task.namespace, task.name),
				"lbID", lbID)
			queue.AddRateLimited(obj)
			return true
		}
	}

	queue.Forget(obj)
	klog.InfoS("service cleanup watcher: finished cleanup for service",
		"service", klog.KRef(task.namespace, task.name),
		"lbIDs", task.lbIDs)
	return true
}

func (lbaas *LbaasV2) clusterIDFromConfigMap(ctx context.Context) (string, error) {
	cm, err := lbaas.kclient.CoreV1().ConfigMaps("kube-system").Get(ctx, "icks-cluster-info", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	clusterID := cm.Data["clusterId"]
	if clusterID == "" {
		return "", fmt.Errorf("icks-cluster-info configmap has empty clusterId")
	}
	return clusterID, nil
}

func wantsKubernetesLoadBalancer(svc *corev1.Service) bool {
	return svc != nil && svc.Spec.Type == corev1.ServiceTypeLoadBalancer && svc.Spec.LoadBalancerClass == nil
}

func serviceHadOpenStackLBAssociation(svc *corev1.Service) bool {
	if svc == nil {
		return false
	}
	if wantsKubernetesLoadBalancer(svc) {
		return true
	}
	for _, key := range lbIDAnnotationKeys() {
		if getStringFromServiceAnnotation(svc, key, "") != "" {
			return true
		}
	}
	return false
}

func shouldCleanupOpenStackLBAfterServiceChange(oldSvc, newSvc *corev1.Service) bool {
	if wantsKubernetesLoadBalancer(newSvc) {
		return false
	}
	return serviceHadOpenStackLBAssociation(oldSvc)
}

func lbIDAnnotationKeys() []string {
	return []string{
		ServiceAnnotationLoadBalancerOldID,
		ServiceAnnotationLoadBalancerID,
		ServiceAnnotationLoadBalancerIDLegacy,
	}
}

func collectLbIDsForServiceCleanup(services ...*corev1.Service) []string {
	seen := sets.NewString()
	var ids []string
	for _, svc := range services {
		if svc == nil {
			continue
		}
		for _, key := range lbIDAnnotationKeys() {
			id := getStringFromServiceAnnotation(svc, key, "")
			if id == "" || seen.Has(id) {
				continue
			}
			seen.Insert(id)
			ids = append(ids, id)
			klog.InfoS("collected LB ID for service cleanup watcher",
				"service", klog.KRef(svc.Namespace, svc.Name),
				"lbID", id,
				"annotation", key)
		}
	}
	return ids
}
