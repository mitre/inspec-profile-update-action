control 'SV-242459' do
  title 'The Kubernetes etcd must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes etcd key-value store provides a way to store data to the Master Node. If these files can be changed, data to API object and master node would be compromised.'
  desc 'check', 'Review the permissions of the Kubernetes etcd by using the command:

stat -c %a  /var/lib/etcd/*

If any of the files are have permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the manifest files to "644" by executing the command:

chmod 644/var/lib/etcd/*'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45734r712731_chk'
  tag severity: 'medium'
  tag gid: 'V-242459'
  tag rid: 'SV-242459r712733_rule'
  tag stig_id: 'CNTR-K8-003260'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45692r712732_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
