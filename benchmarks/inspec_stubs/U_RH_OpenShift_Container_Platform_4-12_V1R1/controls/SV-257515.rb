control 'SV-257515' do
  title 'OpenShift must enforce approved authorizations for controlling the flow of information within the container platform based on organization-defined information flow control policies.'
  desc "OpenShift provides several layers of protection to control the flow of information between the container platform components and user services. Each user project is given a separate namespace and OpenShift enforces RBAC policies controlling which projects and services users can access. In addition, Network Policies are used to control the flow of requests to and from externally integrated services to services hosted on the container platform. 

It is important to define a default Network Policy that will be applied automatically to new projects to prevent unintended requests. These policies can be updated by the project's administrator (with the appropriate RBAC permissions) to apply a policy that is appropriate to the service(s) within the project namespace."
  desc 'check', %q(Check for Network Policy. Verify a default project template is defined by executing the following:

oc get project.config.openshift.io/cluster -o jsonpath="{.spec.projectRequestTemplate.name}"

If no project request template is in use by the project config, this is a finding.

Verify the project request template creates a Network Policy:

oc get templates/<PROJECT-REQUEST-TEMPLATE> -n openshift-config -o jsonpath="{.objects[?(.kind=='NetworkPolicy')]}{'\n'}"

Replace <PROJECT-REQUEST-TEMPLATE> with the name of the project request template returned from the earlier query. If the project template is not defined, or there are no Network Policy definitions in it, this is a finding.)
  desc 'fix', %q(Configure a default network policy as necessary to protect the flow of information by performing the following steps:

1. Create a bootstrap project template (if not already created) by executing the following:

oc adm create-bootstrap-project-template -o yaml > template.yaml

2. Edit the template and add Network Policy object definitions before the parameters section. For example, the following section defines two policies: one to allow requests from the same namespace and one to allow from the OpenShift ingress routing service.

- apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: allow-from-same-namespace
  spec:
    podSelector:
    ingress:
    - from:
      - podSelector: {}
- apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: allow-from-openshift-ingress
  spec:
    ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            network.openshift.io/policy-group: ingress
    podSelector: {}
    policyTypes:
    - Ingress
parameters:

3. Apply the project template to the cluster by executing the following:

oc create -f template.yaml -n openshift-config

4. Set the default cluster project request template by executing the following:
 
oc patch project.config.openshift.io/cluster --type=merge -p '{"spec":{"projectRequestTemplate":{"name": "<PROJECT_REQUEST_TEMPLATE>"}}}'

For additional information regarding network policies, refer to https://docs.openshift.com/container-platform/4.8/networking/network_policy/about-network-policy.html.)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61250r921486_chk'
  tag severity: 'medium'
  tag gid: 'V-257515'
  tag rid: 'SV-257515r921488_rule'
  tag stig_id: 'CNTR-OS-000110'
  tag gtitle: 'SRG-APP-000039-CTR-000110'
  tag fix_id: 'F-61174r921487_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
