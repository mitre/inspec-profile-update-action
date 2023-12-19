control 'SV-223298' do
  title 'User name and password must be disabled in all Office programs.'
  desc 'The Uniform Resource Locator (URL) standard allows user authentication to be included in URL strings in the form http://username:password@example.com. A malicious user might use this URL syntax to create a hyperlink that appears to open a legitimate website but actually opens a deceptive (spoofed) website. For example, the URL http://www.wingtiptoys.com@example.com appears to open http://www.wingtiptoys.com but actually opens http://example.com. To protect users from such attacks, Internet Explorer usually blocks any URLs using this syntax.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security "Disable user name and password" is set to "Enabled" and the check box is selected for every installed Office program.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE

If the value for all installed programs is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security "Disable user name and password" to "Enabled" and select the check boxes for  all installed Office programs.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24971r442113_chk'
  tag severity: 'medium'
  tag gid: 'V-223298'
  tag rid: 'SV-223298r879630_rule'
  tag stig_id: 'O365-CO-000016'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24959r442114_fix'
  tag 'documentable'
  tag legacy: ['SV-108775', 'V-99671']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
