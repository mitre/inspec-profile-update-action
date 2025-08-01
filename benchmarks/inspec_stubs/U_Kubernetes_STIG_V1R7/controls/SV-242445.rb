control 'SV-242445' do
  title 'The Kubernetes component etcd must be owned by etcd.'
  desc 'The Kubernetes etcd key-value store provides a way to store data to the Control Plane. If these files can be changed, data to API object and the Control Plane would be compromised. The scheduler will implement the changes immediately. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Review the ownership of the Kubernetes etcd files by using the command:

stat -c %U:%G /var/lib/etcd/* | grep -v etcd:etcd

If the command returns any non etcd:etcd file permissions, this is a finding.'
  desc 'fix', 'Change the ownership of the manifest files to etcd:etcd by executing the command:

chown etcd:etcd /var/lib/etcd/*'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45720r712689_chk'
  tag severity: 'medium'
  tag gid: 'V-242445'
  tag rid: 'SV-242445r864017_rule'
  tag stig_id: 'CNTR-K8-003120'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45678r712690_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
