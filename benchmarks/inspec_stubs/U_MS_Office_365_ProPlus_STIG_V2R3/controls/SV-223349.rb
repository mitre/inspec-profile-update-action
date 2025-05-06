control 'SV-223349' do
  title 'Scripts associated with shared folders must be prevented from execution in Outlook.'
  desc 'This policy setting controls whether Outlook executes scripts associated with custom forms or folder home pages for shared folders.'
  desc 'check', 'Verify the policy for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Other >> Advanced >> Do not allow Outlook object model scripts to run for shared folders is set to "Enabled".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for sharedfolderscript is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Other >> Advanced >> Do not allow Outlook object model scripts to run for shared folders to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25022r744258_chk'
  tag severity: 'medium'
  tag gid: 'V-223349'
  tag rid: 'SV-223349r744259_rule'
  tag stig_id: 'O365-OU-000004'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25010r442267_fix'
  tag 'documentable'
  tag legacy: ['SV-108877', 'V-99773']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
