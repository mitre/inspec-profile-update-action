control 'SV-223125' do
  title 'Managing SmartScreen Filter use must be enforced.'
  desc "This setting is important from a security perspective because Microsoft has extensive data illustrating the positive impact the SmartScreen filter has had on reducing the risk of malware infection via visiting malicious websites. This policy setting allows users to enable the SmartScreen Filter, which will warn if the website being visited is known for fraudulent attempts to gather personal information through 'phishing' or is known to host malware. If you enable this setting the user will not be prompted to enable the SmartScreen Filter. It must be specified which mode the SmartScreen Filter uses: On or Off. If the feature is On, all website addresses not contained on the filters allow list, will be sent automatically to Microsoft without prompting the user. If this feature is set to Off, the feature will not run. If you disable or do not configure this policy setting, the user is prompted to decide whether to turn on SmartScreen Filter during the first-run experience."
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> "Prevent Managing SmartScreen Filter" must be "Enabled", and "On" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\PhishingFilter 

Criteria: If the value "EnabledV9" is "REG_DWORD = 1", this is not a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> "Prevent Managing SmartScreen Filter" to "Enabled", and select "On" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24798r428925_chk'
  tag severity: 'medium'
  tag gid: 'V-223125'
  tag rid: 'SV-223125r428927_rule'
  tag stig_id: 'DTBI740-IE11'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-24786r428926_fix'
  tag 'documentable'
  tag legacy: ['SV-59685', 'V-46819']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
