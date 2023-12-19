control 'SV-53554' do
  title 'Disabling of user name and password syntax from being used in URLs must be enforced.'
  desc 'The Uniform Resource Locator (URL) standard allows user authentication to be included in URL strings in the form http://username:password@example.com. A malicious user might use this URL syntax to create a hyperlink that appears to open a legitimate website but actually opens a deceptive (spoofed) website. For example, the URL http://www.wingtiptoys.com@example.com appears to open http://www.wingtiptoys.com but actually opens http://example.com. To protect users from such attacks, Internet Explorer usually blocks any URLs using this syntax.

This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If user names and passwords in URLs are allowed, users could be diverted to dangerous web pages, which could pose a security risk.'
  desc 'check', %q(Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Disable user name and password" is set to "Enabled" and a check in the 'winword.exe' check box is selected.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE

Criteria: If the value winword.exe is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine) -> Security Settings -> IE Security "Disable user name and password" to "Enabled" and place a check in the 'winword.exe' check box.)
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17173'
  tag rid: 'SV-53554r1_rule'
  tag stig_id: 'DTOO104'
  tag gtitle: 'DTOO104 - Disable user name and password'
  tag fix_id: 'F-46478r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
