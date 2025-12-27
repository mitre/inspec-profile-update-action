control 'SV-33480' do
  title 'Documents must be configured to not open as Read Write when browsing.'
  desc 'Office document on a Web server using Internet Explorer, the appropriate application opens the file in read-only mode. However, if the default configuration is changed, the document is opened as read/write. Users could potentially make changes to documents and resave them in situations where the Web server security is not configured to prevent such changes.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools \\ Options \\ General \\ Web Options... -> Files “Open Office documents as read/write while browsing” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\internet

Criteria: If the value OpenDocumentsReadWriteWhileBrowsing is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools \\ Options \\ General \\ Web Options... -> Files “Open Office documents as read/write while browsing” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33963r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17759'
  tag rid: 'SV-33480r1_rule'
  tag stig_id: 'DTOO179 - Office System'
  tag gtitle: 'DTOO179 - Open as Read/Write when browsing'
  tag fix_id: 'F-29652r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
