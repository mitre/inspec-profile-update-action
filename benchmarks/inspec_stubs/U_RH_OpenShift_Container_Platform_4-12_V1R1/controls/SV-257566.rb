control 'SV-257566' do
  title 'OpenShift must protect against or limit the effects of all types of Denial-of-Service (DoS) attacks by defining resource quotas on a namespace.'
  desc 'OpenShift allows administrators to define resource quotas on a namespace basis. This allows tailoring of the shared resources based on a project needs. However, when a new project is created, unless a default project resource quota is configured, that project will not have any limits or quotas defined. This could allow someone to create a new project and then deploy services that exhaust or overuse the shared cluster resources.

It is necessary to ensure that all existing namespaces with user-defined workloads have an applied resource quota configured.

Using resource quotas will help to mitigate a DoS attack by limiting how much CPU, memory, and pods may be consumed in a project. This helps protect other projects (namespaces) from being denied resources to process.

https://docs.openshift.com/container-platform/4.8/applications/quotas/quotas-setting-per-project.html

'
  desc 'check', %q(Note: CNTR-OS-000140 is a prerequisite to this control. A Network Policy must exist to run this check.

Verify that each user namespace has a ResourceQuota defined by executing the following:

for ns in $(oc get namespaces -ojson | jq -r '.items[] | select((.metadata.name | startswith("openshift") | not) and (.metadata.name | startswith("kube-") | not) and .metadata.name != "default") | .metadata.name '); do oc get resourcequota -n$ns; done

If the above returns any lines saying "No resources found in <PROJECT> namespace.", this is a finding. Empty output is not a finding.)
  desc 'fix', 'Add a resource quota to an existing project namespace by performing the following steps:

1. Create <YOURFILE>.yaml and insert the desired resource quota content. The following is an example resource quota definition.

apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-resources
  namespace: <NAMESPACE>
spec:
  hard:
    pods: "4" 
    requests.cpu: "1" 
    requests.memory: 1Gi 
    requests.ephemeral-storage: 2Gi 
    limits.cpu: "2" 
    limits.memory: 2Gi 
    limits.ephemeral-storage: 4Gi 

2. Apply the ResourceQuota definition to the project namespace by executing the following:

oc apply -f <YOURFILE>.yaml -n <NAMESPACE>

Details regarding the configuration of resource quotas can be reviewed at https://docs.openshift.com/container-platform/4.8/applications/quotas/quotas-setting-per-project.html.'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61301r921639_chk'
  tag severity: 'medium'
  tag gid: 'V-257566'
  tag rid: 'SV-257566r921641_rule'
  tag stig_id: 'CNTR-OS-000810'
  tag gtitle: 'SRG-APP-000435-CTR-001070'
  tag fix_id: 'F-61225r921640_fix'
  tag satisfies: ['SRG-APP-000435-CTR-001070', 'SRG-APP-000246-CTR-000605', 'SRG-APP-000450-CTR-001105']
  tag 'documentable'
  tag cci: ['CCI-001094', 'CCI-002385', 'CCI-002824']
  tag nist: ['SC-5 (1)', 'SC-5 a', 'SI-16']
end
