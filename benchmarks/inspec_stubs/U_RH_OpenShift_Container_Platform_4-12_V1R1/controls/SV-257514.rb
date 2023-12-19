control 'SV-257514' do
  title 'OpenShift must enforce network policy on the namespace for controlling the flow of information within the container platform based on organization-defined information flow control policies.'
  desc "OpenShift provides several layers of protection to control the flow of information between the container platform components and user services. Each user project is given a separate namespace and OpenShift enforces RBAC policies controlling which projects and services users can access.

OpenShift forces the use of namespaces. Service accounts are a namespace resource as well, so they are segregated. RBAC policies apply to service accounts. In addition, Network Policies are used to control the flow of requests between containers hosted on the container platform.

It is important to define a default Network Policy on the namespace that will be applied automatically to new projects to prevent unintended requests. These policies can be updated by the project's administrator (with the appropriate RBAC permissions) to apply a policy that is appropriate to the service(s) within the project namespace."
  desc 'check', %q(Verify that each user namespace has a Network Policy by executing the following:

for ns in $(oc get namespaces -ojson | jq -r '.items[] | select((.metadata.name | startswith("openshift") | not) and (.metadata.name | startswith("kube-") | not) and .metadata.name != "default") | .metadata.name '); do oc get networkpolicy -n$ns; done

If the above returns any lines saying "No resources found in <PROJECT> namespace.", this is a finding. Empty output is not a finding.)
  desc 'fix', 'Add a Network Policy to an existing project namespace by performing the following steps:

1. Create <YOURFILE>.yaml and insert the desired resource Network Policy content. The following is an example resource quota definition:

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-same-namespace
  namespace: <NAMESPACE>
spec:
  podSelector: {}
  ingress:
  - from:
    - podSelector: {}

2. Apply the Network Policy definition to the project namespace by executing the following:

oc apply -f <YOURFILE>.yaml -n <NAMESPACE>

Details regarding the configuration of resource Network Policy can be reviewed at https://docs.openshift.com/container-platform/4.12/networking/network_policy/about-network-policy.html.'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61249r921483_chk'
  tag severity: 'medium'
  tag gid: 'V-257514'
  tag rid: 'SV-257514r921485_rule'
  tag stig_id: 'CNTR-OS-000100'
  tag gtitle: 'SRG-APP-000038-CTR-000105'
  tag fix_id: 'F-61173r921484_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
