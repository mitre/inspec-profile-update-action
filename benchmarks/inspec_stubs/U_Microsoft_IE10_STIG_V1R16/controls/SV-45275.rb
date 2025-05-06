control 'SV-45275' do
  title 'Managing SmartScreen Filter use must be enforced.'
  desc 'This setting is important from a security perspective because Microsoft has extensive data illustrating the positive impact the SmartScreen filter has had on reducing the risk of malware infection via visiting malicious websites. This policy setting allows users to enable the SmartScreen Filter, which will warn if the website being visited is known for fraudulent attempts to gather personal information through "phishing" or is known to host malware. If you enable this setting the user will not be prompted to enable the SmartScreen Filter. It must be specified which mode the SmartScreen Filter uses: On or Off. If the feature is On, all website addresses not contained on the filters allow list, will be sent automatically to Microsoft without prompting the user. If this feature is set to Off, the feature will not run. If you disable or do not configure this policy setting, the user is prompted to decide whether to turn on SmartScreen Filter during the first-run experience.'
  desc 'check', 'If the system is on SIPRnet, this is NA.

The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> "Prevent Managing SmartScreen Filter" must be "Enabled", and "On" selected from the drop-down box. 

Procedure:
Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\PhishingFilter 

Criteria:
If the value "EnabledV9" is "REG_DWORD = 1", this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> "Prevent Managing SmartScreen Filter" to "Enabled", and select "On" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42622r4_chk'
  tag severity: 'medium'
  tag gid: 'V-22108'
  tag rid: 'SV-45275r3_rule'
  tag stig_id: 'DTBI740'
  tag gtitle: 'DTBI740 - Managing SmartScreen Filter'
  tag fix_id: 'F-38671r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
