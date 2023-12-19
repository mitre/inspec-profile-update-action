control 'SV-242450' do
  title 'The Kubernetes Kubelet certificate authority must be owned by root.'
  desc 'The Kubernetes kube proxy kubeconfig contain the argument and setting for the Master Nodes. These settings contain network rules for restricting network communication between pods, clusters, and networks. If these files can be changed, data traversing between the Kubernetes Control Panel components would be compromised. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Change to the /etc/sysconfig/ directory on the Kubernetes Master Node.
Review the ownership of the Kubernetes  client-ca-file by using the command:
more kubelet
--client-ca-file argument 
Note certificate location

Review the ownership of the Kubernetes client-ca-file by using the command:
stat -c   %U:%G <location from --client-ca-file argument>| grep -v root:root

If the command returns any non root:root file permissions, this is a finding.'
  desc 'fix', 'Change the permissions of the Kube Proxy to "root" by executing the command:

chown root:root <location from kubeconfig>.'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45725r754803_chk'
  tag severity: 'medium'
  tag gid: 'V-242450'
  tag rid: 'SV-242450r754804_rule'
  tag stig_id: 'CNTR-K8-003170'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45683r712705_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
