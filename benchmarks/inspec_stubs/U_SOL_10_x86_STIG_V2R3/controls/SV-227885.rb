control 'SV-227885' do
  title 'The /etc/syslog.conf file must have mode 0640 or less permissive.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'check', 'Check the permissions of the syslog configuration file.
# ls -lL /etc/syslog.conf
If the mode of the file is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the permissions of the syslog configuration file.
# chmod 0640 /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30047r490051_chk'
  tag severity: 'medium'
  tag gid: 'V-227885'
  tag rid: 'SV-227885r603266_rule'
  tag stig_id: 'GEN005390'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30035r490052_fix'
  tag 'documentable'
  tag legacy: ['V-22453', 'SV-26740']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
