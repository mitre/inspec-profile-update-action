control 'SV-218590' do
  title 'The /etc/syslog.conf file must not have an extended ACL.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'check', "Check the permissions of the syslog configuration file.

Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.

# ls -lL /etc/syslog.conf

Or:

# ls -lL /etc/rsyslog.conf

If the permissions include a '+', the file has an extended ACL.

If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all /etc/syslog.conf
 
Or:

# setfacl -- remove-all /etc/rsyslog.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20065r555968_chk'
  tag severity: 'medium'
  tag gid: 'V-218590'
  tag rid: 'SV-218590r603259_rule'
  tag stig_id: 'GEN005395'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20063r555969_fix'
  tag 'documentable'
  tag legacy: ['V-22454', 'SV-63471']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
