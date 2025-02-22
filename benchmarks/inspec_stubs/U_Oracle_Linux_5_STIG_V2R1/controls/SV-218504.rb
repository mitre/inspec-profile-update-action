control 'SV-218504' do
  title 'The xinetd.d directory must not have an extended ACL.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', "Check the permissions of the xinetd configuration files and directories.
# ls -alL /etc/xinetd.conf /etc/xinetd.d
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/xinetd.d'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19979r562645_chk'
  tag severity: 'medium'
  tag gid: 'V-218504'
  tag rid: 'SV-218504r603259_rule'
  tag stig_id: 'GEN003755'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19977r562646_fix'
  tag 'documentable'
  tag legacy: ['V-22426', 'SV-63971']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
