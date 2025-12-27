control 'SV-40704' do
  title 'Managing SmartScreen Filter use must be enforced.'
  desc %q(This setting is important from a security perspective because Microsoft has extensive data illustrating the positive impact the SmartScreen filter has had on reducing the risk of malware infection via visiting malicious web sites. This policy setting allows the users to enable the SmartScreen Filter, which will warn if the web site being visited is known for fraudulent attempts to gather personal information through "phishing" or is known to host malware. If you enable this setting, the user will not be prompted to enable the SmartScreen Filter. It must be specified which mode the SmartScreen Filter uses: on or off. If the feature is on, all web site addresses not contained on the filter's allow list, will be sent automatically to Microsoft without prompting the user. If the feature is off, the user will be prompted to decide the mode of operation for the SmartScreen Filter during the first run experience.)
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Turn off Managing SmartScreen Filter for Internet Explorer 9" must be “Enabled” and “Off” selected from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\PhishingFilter 

Criteria: If the value EnabledV9 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Turn off Managing SmartScreen Filter for Internet Explorer 9" to “Enabled” and select “Off” from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39431r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22108'
  tag rid: 'SV-40704r1_rule'
  tag stig_id: 'DTBI740'
  tag gtitle: 'DTBI740 - Managing SmartScreen Filter'
  tag fix_id: 'F-34560r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
