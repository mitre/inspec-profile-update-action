control 'SV-33496' do
  title 'Automatic download of Internet Calendar appointment attachments must be disallowed.'
  desc 'Files attached to Internet Calendar appointments could contain malicious code that could be used to compromise a computer. By default, Outlook does not download attachments when retrieving Internet Calendar appointments.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> Internet Calendars “Automatically download attachments” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\webcal

Criteria: If the value EnableAttachments is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> Internet Calendars “Automatically download attachments” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17738'
  tag rid: 'SV-33496r1_rule'
  tag stig_id: 'DTOO284 - Outlook'
  tag gtitle: 'DTOO284 - Auto download attachments Internet Cal'
  tag fix_id: 'F-29670r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
