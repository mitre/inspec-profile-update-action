control 'SV-46075' do
  title 'The systems boot loader configuration file(s) must have mode 0600 or less permissive.'
  desc 'File permissions greater than 0600 on boot loader configuration files could allow an unauthorized user to view or modify sensitive information pertaining to system boot instructions.'
  desc 'check', 'Check /etc/zipl.conf permissions:

# ls –lL /etc/zipl.conf

If /etc/zipl.conf has a mode more permissive than 0600, then this is a finding.'
  desc 'fix', 'Change the mode of the zipl.conf file to 0600.

# chmod 0600 /etc/zipl.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43334r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4250'
  tag rid: 'SV-46075r1_rule'
  tag stig_id: 'GEN008720'
  tag gtitle: 'GEN008720'
  tag fix_id: 'F-39421r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
