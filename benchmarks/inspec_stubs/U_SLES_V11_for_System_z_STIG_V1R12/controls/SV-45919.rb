control 'SV-45919' do
  title 'The .Xauthority files must not have extended ACLs.'
  desc '.Xauthority files ensure the user is authorized to access specific X Windows host. Extended ACLs may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', %q(Check the file permissions for the .Xauthority files.

Procedure:
# ls -la |egrep "(\.Xauthority|\.xauth)"
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all .Xauthority'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43227r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22446'
  tag rid: 'SV-45919r1_rule'
  tag stig_id: 'GEN005190'
  tag gtitle: 'GEN005190'
  tag fix_id: 'F-39297r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
