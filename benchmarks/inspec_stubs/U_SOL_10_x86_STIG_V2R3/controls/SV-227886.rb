control 'SV-227886' do
  title 'The /etc/syslog.conf file must not have an extended ACL.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'check', 'Check the permissions of the syslog configuration file.
# ls -lL /etc/syslog.conf
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30048r490054_chk'
  tag severity: 'medium'
  tag gid: 'V-227886'
  tag rid: 'SV-227886r603266_rule'
  tag stig_id: 'GEN005395'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30036r490055_fix'
  tag 'documentable'
  tag legacy: ['V-22454', 'SV-26743']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
