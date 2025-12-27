control 'SV-44757' do
  title 'The /etc/security/access.conf file must not have an extended ACL.'
  desc 'If the access permissions are more permissive than 0640, system security could be compromised.'
  desc 'check', "Check the permissions of the file.
# ls -lLd /etc/security/access.conf
If the permissions of the file or directory contains a '+', an extended ACL is present. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/security/access.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42262r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22595'
  tag rid: 'SV-44757r1_rule'
  tag stig_id: 'GEN000000-LNX00450'
  tag gtitle: 'GEN000000-LNX00450'
  tag fix_id: 'F-38207r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
