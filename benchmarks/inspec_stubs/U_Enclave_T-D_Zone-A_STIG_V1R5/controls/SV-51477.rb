control 'SV-51477' do
  title 'Access to source code during application development must be restricted to authorized users.'
  desc 'Restricting access to source code and the application to authorized users will limit the risk of source code theft or other potential compromise.'
  desc 'check', "Review the organization's site security plan and documentation to determine whether there is a list of current authorized users.  If a current list of authorized users is missing from the site security plan for the test and development environment, this is a finding.

If there isn't any application development occurring in the zone environment, this requirement is not applicable."
  desc 'fix', 'Document all authorized users with access to the development environment and access to source code.   If the documentation exists but is not current, bring the documentation up to date.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone A'
  tag check_id: 'C-46797r3_chk'
  tag severity: 'medium'
  tag gid: 'V-39619'
  tag rid: 'SV-51477r1_rule'
  tag stig_id: 'ENTD0140'
  tag gtitle: 'ENTD0140 - Source code not restricted to authorized individuals.'
  tag fix_id: 'F-44630r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECAN-1, ECCD-1, ECLP-1'
end
