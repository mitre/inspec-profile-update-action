control 'SV-37346' do
  title 'The /etc/passwd file must not have an extended ACL.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.  The /etc/passwd file contains the list of local system accounts. It is vital to system security and must be protected from unauthorized modification.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/passwd'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22334'
  tag rid: 'SV-37346r1_rule'
  tag stig_id: 'GEN001390'
  tag gtitle: 'GEN001390'
  tag fix_id: 'F-23614r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
