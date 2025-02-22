control 'SV-222661' do
  title 'Unnecessary built-in application accounts must be disabled.'
  desc 'Default passwords and properties of built-in accounts are often publicly available. Anyone with necessary knowledge, internal or external, can compromise an application using built-in accounts.

Built-in accounts are those that are added as part of the installation of the application software. These accounts exist for many common Commercial Off-the-Shelf (COTS) or open source components of enterprise applications (e.g., OS, web browser or database software).'
  desc 'check', 'Review the application documentation and identify if the application creates or utilizes built-in accounts.

Examine the account list for obvious examples (e.g., accounts with vendor names such as Oracle or Tivoli).

Verify that these accounts have been removed or disabled.

If enabled built-in accounts are present, ask the application representative the reason for their existence.

If the account is required in order for the application to operate properly, verify the account password has been changed to a DoD acceptable value.

If these accounts are not necessary to run the application, or if the accounts are required and the password has not been changed to meet DoD password requirements, this is a finding.'
  desc 'fix', 'Disable unnecessary built-in userids, use other strong authentication when possible and use strong passwords if accounts are necessary for application operation.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24331r493891_chk'
  tag severity: 'medium'
  tag gid: 'V-222661'
  tag rid: 'SV-222661r508029_rule'
  tag stig_id: 'APSC-DV-003270'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24320r493892_fix'
  tag 'documentable'
  tag legacy: ['V-70401', 'SV-85023']
  tag cci: ['CCI-003109', 'CCI-000366']
  tag nist: ['SA-4 (5) (a)', 'CM-6 b']
end
