control 'SV-254572' do
  title 'Rancher RKE2 must prohibit the installation of patches, updates, and instantiation of container images without explicit privileged status.'
  desc 'Controlling access to those users and roles responsible for patching and updating RKE2 reduces the risk of untested or potentially malicious software from being installed within the platform. This access may be separate from the access required to install container images into the registry and those access requirements required to instantiate an image into a service. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Kubernetes uses the API Server to control communication to the other services that makeup Kubernetes. The use of authorizations and not the default of "AlwaysAllow" enables the Kubernetes functions control to only the groups that need them.

To control access, the API server must have one of the following options set for the authorization mode:
    --authorization-mode=ABAC Attribute-Based Access Control (ABAC) mode allows a user to configure policies using local files.
    --authorization-mode=RBAC Role-based access control (RBAC) mode allows a user to create and store policies using the Kubernetes API.
    --authorization-mode=Webhook
WebHook is an HTTP callback mode that allows a user to manage authorization using a remote REST endpoint.
    --authorization-mode=Node 
Node authorization is a special-purpose authorization mode that specifically authorizes API requests made by kubelets.
    --authorization-mode=AlwaysDeny 
This flag blocks all requests. Use this flag only for testing.

'
  desc 'check', 'Ensure authorization-mode is set correctly in the apiserver.

Run this command on the RKE2 Control Plane:
/bin/ps -ef | grep kube-apiserver | grep -v grep

If  --authorization-mode is not set to "RBAC,Node" or is not configured, this is a finding.
(By default, RKE2 sets Node,RBAC as the parameter to the --authorization-mode argument.)'
  desc 'fix', 'Edit the /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml file. 
--authorization-mode=RBAC,Node

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58056r859284_chk'
  tag severity: 'medium'
  tag gid: 'V-254572'
  tag rid: 'SV-254572r859286_rule'
  tag stig_id: 'CNTR-R2-001270'
  tag gtitle: 'SRG-APP-000378-CTR-000880'
  tag fix_id: 'F-58005r859285_fix'
  tag satisfies: ['SRG-APP-000378-CTR-000880', 'SRG-APP-000378-CTR-000885']
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
