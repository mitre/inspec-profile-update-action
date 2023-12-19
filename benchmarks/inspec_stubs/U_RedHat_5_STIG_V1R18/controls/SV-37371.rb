control 'SV-37371' do
  title 'The /etc/shadow file must not have an extended ACL.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', "Verify /etc/shadow has no extended ACL.
# ls -l /etc/shadow
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/shadow'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36058r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22340'
  tag rid: 'SV-37371r1_rule'
  tag stig_id: 'GEN001430'
  tag gtitle: 'GEN001430'
  tag fix_id: 'F-31303r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
