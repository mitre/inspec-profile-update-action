control 'SV-242454' do
  title 'The Kubernetes kubeadm.conf must be owned by root.'
  desc 'The Kubernetes kubeeadm.conf contains sensitive information regarding the cluster nodes configuration. If this file can be modified, the Kubernetes Platform Plane would be degraded or compromised for malicious intent. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Review the Kubeadm.conf file :

Get the path for Kubeadm.conf by running: 
sytstemctl status kubelet

Note the configuration file installed by the kubeadm is written to 
(Default Location: /etc/systemd/system/kubelet.service.d/10-kubeadm.conf)
stat -c %U:%G <kubeadm.conf path> | grep -v root:root

If the command returns any non root:root file permissions, this is a finding.'
  desc 'fix', 'Change the ownership of the kubeadm.conf to root: root by executing the command:

chown root:root <kubeadm.conf path>'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45729r754817_chk'
  tag severity: 'medium'
  tag gid: 'V-242454'
  tag rid: 'SV-242454r879887_rule'
  tag stig_id: 'CNTR-K8-003210'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45687r754818_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
