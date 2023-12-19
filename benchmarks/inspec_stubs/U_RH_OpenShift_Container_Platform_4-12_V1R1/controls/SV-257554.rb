control 'SV-257554' do
  title 'OpenShift must restrict individuals the ability to launch organizational-defined Denial-of-Service (DOS) attacks against other information systems by setting a default Resource Quota.'
  desc 'OpenShift allows administrators to define resource quotas on a namespace basis. This allows tailoring of the shared resources based on a project needs. However, when a new project is created, unless a default project resource quota is configured, that project will not have any limits or quotas defined. This could allow someone to create a new project and then deploy services that exhaust or overuse the shared cluster resources. Thus, it is necessary to ensure that there is a default resource quota configured for all new projects. A Cluster Admin may increase resource quotas on a given project namespace, if that project requires additional resources at any time.'
  desc 'check', %q(Check for Resource Quota. Verify a default project template is defined by executing the following:

oc get project.config.openshift.io/cluster -o jsonpath="{.spec.projectRequestTemplate.name}"

If no project request template is in use by the project config, this is a finding.

Verify the project template includes a default resource quota.

oc get templates/<PROJECT-REQUEST-TEMPLATE> -n openshift-config -o jsonpath="{.objects[?(.kind=='ResourceQuota')]}{'\n'}"

Replace <PROJECT-REQUEST-TEMPLATE> with the name of the project request template returned from the earlier query.

If the project template is not defined, or there are no ResourceQuota definitions in it, this is a finding.)
  desc 'fix', %q(Configure a default resource quota to protect resource over utilization by performing the following steps:

1. Create a bootstrap project template (if not already created) by executing the following:

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

4. Set the default cluster project request template by executing the following:
 
oc patch project.config.openshift.io/cluster --type=merge -p '{"spec":{"projectRequestTemplate":{"name": "<PROJECT_REQUEST_TEMPLATE>"}}}'

Details regarding the configuration of resource quotas can be reviewed at https://docs.openshift.com/container-platform/4.8/applications/quotas/quotas-setting-per-project.html.)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61289r921603_chk'
  tag severity: 'medium'
  tag gid: 'V-257554'
  tag rid: 'SV-257554r921605_rule'
  tag stig_id: 'CNTR-OS-000620'
  tag gtitle: 'SRG-APP-000246-CTR-000605'
  tag fix_id: 'F-61213r921604_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
