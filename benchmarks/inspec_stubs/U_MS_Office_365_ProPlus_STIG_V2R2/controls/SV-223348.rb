control 'SV-223348' do
  title 'Scripts associated with public folders must be prevented from execution in Outlook.'
  desc 'This policy setting controls whether Outlook executes scripts that are associated with custom forms or folder home pages for public folders.'
  desc 'check', 'Verify the policy for Microsoft Outlook 2016 >> Outlook Options >> Other >> Advanced >> Do not allow Outlook object model scripts to run for public folders is set to "Enabled".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for publicfolderscript is set to REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Other >> Advanced >> Do not allow Outlook object model scripts to run for public folders to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25021r442263_chk'
  tag severity: 'medium'
  tag gid: 'V-223348'
  tag rid: 'SV-223348r508019_rule'
  tag stig_id: 'O365-OU-000003'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25009r442264_fix'
  tag 'documentable'
  tag legacy: ['SV-108875', 'V-99771']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
