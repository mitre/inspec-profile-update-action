control 'SV-37682' do
  title 'The .Xauthority files must not have extended ACLs.'
  desc '.Xauthority files ensure the user is authorized to access specific X Windows host. Extended ACLs may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', %q(Check the file permissions for the .Xauthority files.  These files will be located in user home directories.

Procedure:
# ls -la ~username |egrep "(\.Xauthority|\.xauth)"

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all .Xauthority'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36869r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22446'
  tag rid: 'SV-37682r1_rule'
  tag stig_id: 'GEN005190'
  tag gtitle: 'GEN005190'
  tag fix_id: 'F-31834r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
