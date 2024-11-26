control 'SV-242446' do
  title 'The Kubernetes conf files must be owned by root.'
  desc 'The Kubernetes conf files contain the arguments and settings for the Control Plane services. These services are controller and scheduler. If these files can be changed, the scheduler will be implementing the changes immediately. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Review the Kubernetes conf files by using the command:

stat -c %U:%G /etc/kubernetes/admin.conf | grep -v root:root
stat -c %U:%G /etc/kubernetes/scheduler.conf | grep -v root:root
stat -c %U:%G /etc/kubernetes/controller-manager.conf | grep -v root:root

If the command returns any non root:root file permissions, this is a finding.'
  desc 'fix', 'Change the ownership of the conf files to root: root by executing the command:

chown root:root /etc/kubernetes/admin.conf 
chown root:root /etc/kubernetes/scheduler.conf 
chown root:root /etc/kubernetes/controller-manager.conf'
  impact 0.5
  ref 'DPMS Target Kubernetes'
  tag check_id: 'C-45721r712692_chk'
  tag severity: 'medium'
  tag gid: 'V-242446'
  tag rid: 'SV-242446r864018_rule'
  tag stig_id: 'CNTR-K8-003130'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45679r712693_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
