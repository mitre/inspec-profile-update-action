control 'SV-218502' do
  title 'The inetd.conf and xinetd.conf files must not have extended ACLs.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', "Check the permissions of the xinetd configuration files. 

Procedure:
# ls -alL /etc/xinetd.conf
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/xinetd.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19977r562639_chk'
  tag severity: 'medium'
  tag gid: 'V-218502'
  tag rid: 'SV-218502r603259_rule'
  tag stig_id: 'GEN003745'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19975r562640_fix'
  tag 'documentable'
  tag legacy: ['V-22424', 'SV-64241']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
