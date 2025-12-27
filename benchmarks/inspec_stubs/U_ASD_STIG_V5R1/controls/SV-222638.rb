control 'SV-222638' do
  title 'Data backup must be performed at required intervals in accordance with DoD policy.'
  desc 'Without proper backups, the application is not protected from the loss of data or the operating environment in the event of hardware or software failure.'
  desc 'check', 'Interview the application and system admins and review documented backup procedures.

Check the following based on the risk level of the application.

For low risk applications:

Validate backup procedures exist and are performed at least weekly.

A sampling of system backups should be checked to ensure compliance with the control.

For medium risk applications:

Validate backup procedures exist and are performed at least daily.

Validate recovery media is stored at an off-site location and ensure the data is protected in accordance with its risk category and confidentiality level. This validation can be performed by examining an SLA or MOU/MOA that states the protection levels of the data and how it should be stored.

A sampling of system backups should be checked to ensure compliance with the control.

Verify that the organization tests backup information to ensure media reliability and information integrity.

Verify that the organization selectively uses backup information in the restoration of information system functions as part of annual contingency plan testing.

For high risk applications:

Validate that the procedures have been defined for system redundancy and they are properly implemented and are executing the procedures.

Verify that the redundant system is properly separated from the primary system (i.e., located in a different building or in a different city). This validation should be performed by examining the secondary system and ensuring its operation.

Examine the SLA or MOU/MOA to ensure redundant capability is addressed. Finding details should indicate the type of validation performed. Examine the mirror capability testing procedures and results to insure the capability is properly tested at 6 month minimum intervals.

If any of the requirements above for the associated risk level of the application are not met, this is a finding.'
  desc 'fix', 'Develop and implement backup procedures based on risk level of the system and in accordance with DoD policy.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24308r493822_chk'
  tag severity: 'medium'
  tag gid: 'V-222638'
  tag rid: 'SV-222638r508029_rule'
  tag stig_id: 'APSC-DV-003070'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24297r493823_fix'
  tag 'documentable'
  tag legacy: ['SV-84977', 'V-70355']
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
