control 'SV-222646' do
  title 'At least one tester must be designated to test for security flaws in addition to functional testing.'
  desc 'If there is no person designated to test for security flaws, vulnerabilities can potentially be missed during testing.

This requirement is meant to apply to developers or organizations that are doing development work.'
  desc 'check', 'Review the organization chart and interview the admin staff.

Identify personnel designated as application security testers.

If the organization operating the application is not doing development work, this requirement is not applicable.

If the organization has not designated personnel to conduct security testing, this is a finding.'
  desc 'fix', 'Designate personnel to conduct security testing on the applications.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24316r493846_chk'
  tag severity: 'medium'
  tag gid: 'V-222646'
  tag rid: 'SV-222646r508029_rule'
  tag stig_id: 'APSC-DV-003150'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24305r493847_fix'
  tag 'documentable'
  tag legacy: ['SV-84993', 'V-70371']
  tag cci: ['CCI-000366', 'CCI-003182']
  tag nist: ['CM-6 b', 'SA-11 (2)']
end
