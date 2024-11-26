control 'SV-218295' do
  title 'The /etc/passwd file must not have an extended ACL.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.  The /etc/passwd file contains the list of local system accounts. It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', "Verify /etc/passwd has no extended ACL.

# ls -l /etc/passwd

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all /etc/passwd'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19770r561674_chk'
  tag severity: 'medium'
  tag gid: 'V-218295'
  tag rid: 'SV-218295r603259_rule'
  tag stig_id: 'GEN001390'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19768r561675_fix'
  tag 'documentable'
  tag legacy: ['V-22334', 'SV-64559']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
