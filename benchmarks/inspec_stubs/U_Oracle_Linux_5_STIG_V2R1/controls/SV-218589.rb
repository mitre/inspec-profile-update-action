control 'SV-218589' do
  title 'The /etc/syslog.conf file must have mode 0640 or less permissive.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'check', 'Check the permissions of the syslog configuration file.

Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.

# ls -lL /etc/syslog.conf

Or:

# ls -lL /etc/rsyslog.conf

If the mode of the file is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the permissions of the syslog or rsyslog configuration file.

# chmod 0640 /etc/syslog.conf
 
Or:

# chmod 0640 /etc/rsyslog.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20064r555965_chk'
  tag severity: 'medium'
  tag gid: 'V-218589'
  tag rid: 'SV-218589r603259_rule'
  tag stig_id: 'GEN005390'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20062r555966_fix'
  tag 'documentable'
  tag legacy: ['V-22453', 'SV-63467']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
