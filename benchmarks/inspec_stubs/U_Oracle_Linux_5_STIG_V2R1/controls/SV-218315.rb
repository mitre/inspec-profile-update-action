control 'SV-218315' do
  title 'All files and directories contained in user home directories must not have extended ACLs.'
  desc 'Excessive permissions allow unauthorized access to user files.'
  desc 'check', "Check the contents of user home directories for files with extended ACLs.
# cut -d : -f 6 /etc/passwd | xargs -n1 -IDIR ls -alLR DIR
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <user file with extended ACL>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19790r554282_chk'
  tag severity: 'medium'
  tag gid: 'V-218315'
  tag rid: 'SV-218315r603259_rule'
  tag stig_id: 'GEN001570'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19788r554283_fix'
  tag 'documentable'
  tag legacy: ['V-22352', 'SV-63839']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
