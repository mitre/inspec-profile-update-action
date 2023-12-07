control 'SV-37210' do
  title 'All system command files must not have extended ACLs.'
  desc "Restricting permissions will protect system command files from unauthorized modification.  System command files include files present in directories used by the operating system for storing default system executables and files present in directories included in the system's default executable search paths."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22314'
  tag rid: 'SV-37210r1_rule'
  tag stig_id: 'GEN001210'
  tag gtitle: 'GEN001210'
  tag fix_id: 'F-31159r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
