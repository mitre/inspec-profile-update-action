control 'SV-222650' do
  title 'Flaws found during a code review must be tracked in a defect tracking system.'
  desc 'This requirement is meant to apply to developers or organizations that are doing application development work.

If flaws are not tracked they may possibly be forgotten to be included in a release. Tracking flaws in the configuration management repository will help identify code elements to be changed, as well as the requested change.'
  desc 'check', 'This requirement is meant to apply to developers or organizations that are doing application development work.

If application development is not being done or managed by the organization, this requirement is not applicable.

Ask the application representative to demonstrate that the configuration management repository captures flaws in the code review process. The configuration management repository may consist of a separate application for capturing code defects.

If there is no configuration management repository or the code review flaws are not captured in the configuration management repository, this is a finding.'
  desc 'fix', 'Track software defects in a defect tracking system.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24320r493858_chk'
  tag severity: 'medium'
  tag gid: 'V-222650'
  tag rid: 'SV-222650r864432_rule'
  tag stig_id: 'APSC-DV-003190'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24309r493859_fix'
  tag 'documentable'
  tag legacy: ['SV-85001', 'V-70379']
  tag cci: ['CCI-003197']
  tag nist: ['SA-11 (8)']
end
