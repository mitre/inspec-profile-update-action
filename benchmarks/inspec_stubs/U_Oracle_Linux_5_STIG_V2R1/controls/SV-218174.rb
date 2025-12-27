control 'SV-218174' do
  title 'The access.conf file must not have an extended ACL.'
  desc 'If the access permissions are more permissive than 0640, system security could be compromised.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/security/access.conf
If the permissions of the file or directory contain a '+', an extended ACL is present. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/security/access.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19649r553859_chk'
  tag severity: 'medium'
  tag gid: 'V-218174'
  tag rid: 'SV-218174r603259_rule'
  tag stig_id: 'GEN000000-LNX00450'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19647r553860_fix'
  tag 'documentable'
  tag legacy: ['V-22595', 'SV-62909']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
