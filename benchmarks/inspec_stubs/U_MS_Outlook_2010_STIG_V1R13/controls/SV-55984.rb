control 'SV-55984' do
  title 'Text in Outlook that represents Internet and network paths must not be automatically turned into hyperlinks.'
  desc 'The ability of Outlook to automatically turn text that represents Internet and network paths into hyperlinks would allow users to click on those hyperlinks in email messages and access malicious or otherwise harmful websites.'
  desc 'check', 'The intent of this check is to block the display of Internet and network paths as hyperlinks in email messages. This requirement cannot be configured in the Office 2010 Administrative Templates. It can either be configured individually, within each Outlook client, or by registry key. 

To verify within the Outlook client that "Internet and network path into hyperlinks" is not enabled:

From the main Outlook window, go to Tools>>Options.
Select the "Mail Format" tab.
Select the "Editor Options" button.
In the left pane, select the "Proofing" button.
Select the "AutoCorrect" button.
Select the "AutoFormat As You Type" tab.

Criteria: If the "Internet and network path into hyperlinks" checkbox is selected, this is a finding.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\14.0\\outlook\\options\\autoformat

Criteria: If the value pgrfafo_25_1 is REG_DWORD = 1, this is a finding.'
  desc 'fix', 'Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\14.0\\outlook\\options\\autoformat

If the REG_DWORD value for pgrfafo_25_1 does not exist, create it with a value of "0". 

If the REG_DWORD value for pgrfafo_25_1 does exist, change the value to "0".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-49263r4_chk'
  tag severity: 'medium'
  tag gid: 'V-41493'
  tag rid: 'SV-55984r2_rule'
  tag stig_id: 'DTOO425'
  tag gtitle: 'DTOO425 - Disable Internet and network path into hyperlinks'
  tag fix_id: 'F-48823r5_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
