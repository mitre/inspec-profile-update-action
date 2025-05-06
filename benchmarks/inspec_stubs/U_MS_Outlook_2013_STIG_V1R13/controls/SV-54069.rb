control 'SV-54069' do
  title 'Text in Outlook that represents Internet and network paths must not be automatically turned into hyperlinks.'
  desc 'The ability of Outlook to automatically turn text that represents Internet and network paths into hyperlinks would allow users to click on those hyperlinks in email message and access malicious or otherwise harmful websites.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> "Internet and network path into hyperlinks" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\15.0\\outlook\\options\\autoformat

Criteria: If the value pgrfafo_25_1 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> "Internet and network path into hyperlinks" must be set to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-48009r1_chk'
  tag severity: 'medium'
  tag gid: 'V-41493'
  tag rid: 'SV-54069r1_rule'
  tag stig_id: 'DTOO425'
  tag gtitle: 'DTOO425 - Disable Internet and network path into hyperlinks'
  tag fix_id: 'F-46949r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
