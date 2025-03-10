control 'SV-218713' do
  title 'Automated file system mounting tools must not be enabled unless needed.'
  desc "Automated file system mounting tools may provide unprivileged users with the ability to access local media and network shares. If this access is not necessary for the system's operation, it must be disabled to reduce the risk of unauthorized access to these resources."
  desc 'check', 'If the autofs service is needed, this vulnerability is not applicable.
Check if the autofs service is running.
# service autofs status
If the service is running, this is a finding.'
  desc 'fix', 'Stop and disable the autofs service.
# service autofs stop
# chkconfig autofs off'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20188r556556_chk'
  tag severity: 'low'
  tag gid: 'V-218713'
  tag rid: 'SV-218713r603259_rule'
  tag stig_id: 'GEN008440'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20186r556557_fix'
  tag 'documentable'
  tag legacy: ['V-22577', 'SV-63193']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
