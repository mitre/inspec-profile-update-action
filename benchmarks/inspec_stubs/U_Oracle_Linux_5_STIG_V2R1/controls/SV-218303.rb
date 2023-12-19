control 'SV-218303' do
  title 'The /etc/shadow file must not have an extended ACL.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', "Verify /etc/shadow has no extended ACL.

# ls -l /etc/shadow

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all /etc/shadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19778r561698_chk'
  tag severity: 'medium'
  tag gid: 'V-218303'
  tag rid: 'SV-218303r603259_rule'
  tag stig_id: 'GEN001430'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19776r561699_fix'
  tag 'documentable'
  tag legacy: ['V-22340', 'SV-64575']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
