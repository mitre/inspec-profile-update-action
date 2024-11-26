control 'SV-228543' do
  title 'Documents must be configured to not open as Read Write when browsing.'
  desc 'By default, when an Office 2013 document on a web server is opened using Internet Explorer, the appropriate application opens the file in read-only mode. However, if the default configuration is changed, the document is opened as read/write. Users could potentially make changes to documents and resave them in situations where the web server security is not configured to prevent such changes.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Tools | Options | General | Web Options... >> Files "Open Office documents as read/write while browsing" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\internet

If the value 'OpenDocumentsReadWriteWhileBrowsing' for REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Tools | Options | General | Web Options... >> Files "Open Office documents as read/write while browsing" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30776r498907_chk'
  tag severity: 'medium'
  tag gid: 'V-228543'
  tag rid: 'SV-228543r508020_rule'
  tag stig_id: 'DTOO179'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-30761r498908_fix'
  tag 'documentable'
  tag legacy: ['V-17759', 'SV-52714']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
