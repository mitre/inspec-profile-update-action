control 'SV-37216' do
  title 'All system files, programs, and directories must be owned by a system account.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'fix', 'Change the owner of system files, programs, and directories to a system account.

Procedure:
# chown root /some/system/file

(A different system user may be used in place of root.)'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-795'
  tag rid: 'SV-37216r1_rule'
  tag stig_id: 'GEN001220'
  tag gtitle: 'GEN001220'
  tag fix_id: 'F-31164r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
