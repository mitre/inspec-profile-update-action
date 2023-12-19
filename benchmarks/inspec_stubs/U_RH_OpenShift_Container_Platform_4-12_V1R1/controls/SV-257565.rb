control 'SV-257565' do
  title 'OpenShift must protect against or limit the effects of all types of Denial-of-Service (DoS) attacks by employing organization-defined security safeguards by including a default resource quota.'
  desc 'DNS attacks that are internal to the container platform (exploited or otherwise malicious applications) can have a limited blast radius by adhering to least privilege RBAC and Network access:
https://docs.openshift.com/container-platform/4.8/post_installation_configuration/network-configuration.html#post-install-configuring-network-policy

Additionally, applications can even be limited using OpenShift Service Mesh Operator.

DoS attacks coming from outside the cluster (ingress) can also be limited using an external cloud load balancer or by using 3scale API Gateway:
https://docs.openshift.com/container-platform/4.8/security/container_security/security-platform.html

Resource quotas must be set on a given namespace or across multiple namespaces. Using resource quotas will help to mitigate a DoS attack by limiting how much CPU, memory, and pods may be consumed in a project. This helps protect other projects (namespaces) from being denied resources to process.

https://docs.openshift.com/container-platform/4.8/applications/quotas/quotas-setting-per-project.html'
  desc 'check', %q(Verify the new project template includes a default resource quota by executing the following:

oc get templates/project-request -n openshift-config -o jsonpath="{.objects[?(.kind=='ResourceQuota')]}{'\n'}"

Review the ResourceQuota definition. If nothing is return, this is a finding.)
  desc 'fix', 'Configure a default resource quota as necessary to protect resource over utilization.

1. Create a bootstrap project template by executing the following:

oc adm create-bootstrap-project-template -o yaml > template.yaml

2. Edit the template and add a ResourceQuota object definition before the parameters section.

- apiVersion: v1
  kind: ResourceQuota
  metadata:
    name: example
  spec:
    hard:
      persistentvolumeclaims: "10"
      requests.storage: "50Gi"
      ...
parameters:

3. Apply the project template to the cluster by executing the following:

oc create -f template.yaml -n openshift-config

Details regarding the configuration of resource quotas can be reviewed at https://docs.openshift.com/container-platform/4.8/applications/quotas/quotas-setting-per-project.html.'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61300r921636_chk'
  tag severity: 'medium'
  tag gid: 'V-257565'
  tag rid: 'SV-257565r921638_rule'
  tag stig_id: 'CNTR-OS-000800'
  tag gtitle: 'SRG-APP-000435-CTR-001070'
  tag fix_id: 'F-61224r921637_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
