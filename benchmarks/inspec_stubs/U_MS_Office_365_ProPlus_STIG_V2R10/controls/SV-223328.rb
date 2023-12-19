control 'SV-223328' do
  title 'Updating of links in Excel must be prompted and not automatic.'
  desc 'This policy setting controls whether Excel prompts users to update automatic links, or whether the updates occur in the background with no prompt.

If you enable or do not configure this policy setting, Excel will prompt users to update automatic links. In addition, the "Ask to update automatic links" user interface option under File tab >> Advanced >> General is selected.

If you disable this policy setting, Excel updates automatic links without prompting or informing users, which could compromise the integrity of some of the information in the workbook.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Advanced >> Ask to update automatic links is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\options\\binaryoptions

If the value for fupdateext_78_1 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Advanced >> Ask to update automatic links to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25001r744250_chk'
  tag severity: 'medium'
  tag gid: 'V-223328'
  tag rid: 'SV-223328r879630_rule'
  tag stig_id: 'O365-EX-000019'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24989r442204_fix'
  tag 'documentable'
  tag legacy: ['SV-108835', 'V-99731']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
