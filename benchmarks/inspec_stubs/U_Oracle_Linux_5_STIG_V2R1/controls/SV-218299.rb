control 'SV-218299' do
  title 'The /etc/group file must not have an extended ACL.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', "Verify /etc/group has no extended ACL.

# ls -l /etc/group

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all /etc/group'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19774r561686_chk'
  tag severity: 'medium'
  tag gid: 'V-218299'
  tag rid: 'SV-218299r603259_rule'
  tag stig_id: 'GEN001394'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19772r561687_fix'
  tag 'documentable'
  tag legacy: ['V-22338', 'SV-64567']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
