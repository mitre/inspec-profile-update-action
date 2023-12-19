control 'SV-218247' do
  title 'The root accounts home directory must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the UNIX permissions of the files.'
  desc 'check', "Check the root account's home directory has no extended ACL.

# find ~root -type d -prune -exec ls -ld {} \\;

If the permissions include a '+' the directory has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', "Remove the extended ACL from the root account's home directory.
# setfacl --remove-all <root home directory>"
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19722r568684_chk'
  tag severity: 'medium'
  tag gid: 'V-218247'
  tag rid: 'SV-218247r603259_rule'
  tag stig_id: 'GEN000930'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19720r568685_fix'
  tag 'documentable'
  tag legacy: ['V-22309', 'SV-64363']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
