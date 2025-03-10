control 'SV-218572' do
  title 'The .Xauthority files must not have extended ACLs.'
  desc '.Xauthority files ensure the user is authorized to access specific X Windows host. Extended ACLs may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', %q(Check the file permissions for the .Xauthority files.  These files will be located in user home directories.

Procedure:
# ls -la ~username |egrep "(\.Xauthority|\.xauth)"

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all .Xauthority'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20047r555914_chk'
  tag severity: 'medium'
  tag gid: 'V-218572'
  tag rid: 'SV-218572r603259_rule'
  tag stig_id: 'GEN005190'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20045r555915_fix'
  tag 'documentable'
  tag legacy: ['V-22446', 'SV-63285']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
