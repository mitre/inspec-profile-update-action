control 'SV-45762' do
  title 'The xinetd.d directory must not have an extended ACL.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', "Check the permissions of the xinetd configuration files and directories.
# ls -alL /etc/xinetd.conf /etc/xinetd.d
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/xinetd.d'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43116r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22426'
  tag rid: 'SV-45762r1_rule'
  tag stig_id: 'GEN003755'
  tag gtitle: 'GEN003755'
  tag fix_id: 'F-39162r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
