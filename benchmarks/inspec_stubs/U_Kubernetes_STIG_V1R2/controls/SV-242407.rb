control 'SV-242407' do
  title 'The Kubernetes kubelet configuration file must be owned by root.'
  desc 'The kubelet configuration file contains the runtime configuration of the kubelet service. If an attacker can gain access to this file, changes can be made to open vulnerabilities and bypass user authorizations inherit within Kubernetes with RBAC implemented.'
  desc 'check', 'On the Master and worker nodes, change to the /etc/kubernetes/manifest directory. Run the command:

ls -l kubelet

Each kubelet configuration file must have permissions of "644" or more restrictive.

If any kubelet configuration file is less restrictive than "644", this is a finding.'
  desc 'fix', 'On the Master node, change to the /etc/kubernetes/manifest directory. Run the command:

chmod 644 kubelet

To verify the change took place, run the command:

ls -l kubelet

The kubelet file should now have the permissions of "644".'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45682r712575_chk'
  tag severity: 'medium'
  tag gid: 'V-242407'
  tag rid: 'SV-242407r712577_rule'
  tag stig_id: 'CNTR-K8-000890'
  tag gtitle: 'SRG-APP-000133-CTR-000305'
  tag fix_id: 'F-45640r712576_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
