control 'SV-242455' do
  title 'The Kubernetes kubelet service must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes kubeadm.conf contains sensitive information regarding the cluster nodes configuration. If this file can be modified, the Kubernetes Platform Plane would be degraded or compromised for malicious intent. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Review the permissions of the Kubernetes kubelet by using the command:

stat -c %a /usr/bin/kubeadm

If any of the files have permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of Kubeadm to "644" by executing the command:

chown 644 /usr/bin/kubeadm'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45730r712719_chk'
  tag severity: 'medium'
  tag gid: 'V-242455'
  tag rid: 'SV-242455r712721_rule'
  tag stig_id: 'CNTR-K8-003220'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45688r712720_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
