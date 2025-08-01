control 'SV-242447' do
  title 'The Kubernetes Kube Proxy must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes kube proxy kubeconfig contain the argument and setting for the Control Planes. These settings contain network rules for restricting network communication between pods, clusters, and networks. If these files can be changed, data traversing between the Kubernetes Control Panel components would be compromised. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Check if Kube-Proxy is running and obtain --kubeconfig parameter use the following command:
ps -ef | grep kube-proxy

If Kube-Proxy exists:
Review the permissions of the Kubernetes Kube Proxy by using the command:
stat -c %a <location from --kubeconfig>

If the file has permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the Kube Proxy to "644" by executing the command:

chmod 644 <location from kubeconfig>.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45722r712695_chk'
  tag severity: 'medium'
  tag gid: 'V-242447'
  tag rid: 'SV-242447r864019_rule'
  tag stig_id: 'CNTR-K8-003140'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45680r821611_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
