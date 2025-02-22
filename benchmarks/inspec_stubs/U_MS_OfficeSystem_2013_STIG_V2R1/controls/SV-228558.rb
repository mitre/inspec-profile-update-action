control 'SV-228558' do
  title 'Hyperlink warnings for Office must be configured for use.'
  desc 'Unsafe hyperlinks are links that might pose a security risk if users click them. Clicking an unsafe link could compromise the security of sensitive information or harm the computer.
Links that Office considers unsafe include links to executable files, TIFF files, and Microsoft Document Imaging (MDI) files. Other unsafe links are those using protocols considered to be unsafe, including msn, nntp, mms, outlook, and stssync.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "Suppress hyperlink warnings" is set to "Disabled".
Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\security

Criteria: If the value 'DisableHyperLinkWarning' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings "Suppress hyperlink warnings" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30791r498952_chk'
  tag severity: 'medium'
  tag gid: 'V-228558'
  tag rid: 'SV-228558r508020_rule'
  tag stig_id: 'DTOO194'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-30776r498953_fix'
  tag 'documentable'
  tag legacy: ['SV-52731', 'V-17659']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
