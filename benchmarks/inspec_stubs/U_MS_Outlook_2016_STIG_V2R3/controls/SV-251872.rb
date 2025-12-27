control 'SV-251872' do
  title 'Text in Outlook that represents internet and network paths must not be automatically turned into hyperlinks.'
  desc 'The ability of Outlook to automatically turn text that represents internet and network paths into hyperlinks would allow users to click on those hyperlinks in an email message and access malicious or otherwise harmful websites.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> "Internet and network path into hyperlinks" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\16.0\\outlook\\options\\autoformat

Criteria: If the value pgrfafo_25_1 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> "Internet and network path into hyperlinks" must be set to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-55329r811193_chk'
  tag severity: 'medium'
  tag gid: 'V-251872'
  tag rid: 'SV-251872r812968_rule'
  tag stig_id: 'DTOO425'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-55284r811194_fix'
  tag 'documentable'
  tag legacy: ['SV-57685', 'V-44851']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
