control 'SV-45760' do
  title 'The inetd.conf and xinetd.conf files must not have extended ACLs.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', "Check the permissions of the xinetd configuration files. 

Procedure:
# ls -alL /etc/xinetd.conf
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/xinetd.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43114r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22424'
  tag rid: 'SV-45760r1_rule'
  tag stig_id: 'GEN003745'
  tag gtitle: 'GEN003745'
  tag fix_id: 'F-39160r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
