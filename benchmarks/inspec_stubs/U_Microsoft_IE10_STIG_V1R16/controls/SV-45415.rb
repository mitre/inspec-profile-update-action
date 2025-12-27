control 'SV-45415' do
  title 'The Internet Explorer TLS parameter must be set correctly.'
  desc "This parameter ensures only DoD-approved ciphers and algorithms are enabled for use by the web browser. TLS is a protocol for protecting communications between the browser and the target server. When the browser attempts to set up a protected communication with the target server, the browser and server negotiate which protocol and version to use. The browser and server attempt to match each other's list of supported protocols and versions and pick the most preferred match."
  desc 'check', 'Open Internet Explorer. From the menu bar, select "Tools". From the "Tools" drop-down menu, select "Internet Options".
From the "Internet Options" window, select the "Advanced" tab, from the "Advanced" tab window scroll down to the "Security" category.

Verify a checkmark is placed in the "Use TLS 1.1", and "Use TLS 1.2" check boxes.
Verify there is not a check placed in the check box for "Use SSL 2.0", "Use SSL 3.0", or "Use TLS 1.0."

If "Use SSL 2.0", "Use SSL 3.0", or "Use TLS 1.0" is checked, this is a finding.

1) The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Advanced Page >> "Turn off Encryption Support" must be "Enabled" and ensure the options selected are "Use TLS 1.1", and "Use TLS 1.2" from the drop-down box.

If the selected options contain "SSL 2.0", "SSL 3.0",or "Use TLS 1.0", this is a finding. 

2) The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> "Allow fallback to SSL 3.0 (Internet Explorer)" must be "Enabled", and "No Sites" selected from the drop-down box.

If "Allow fallback to SSL 3.0 (Internet Explorer)" is not "Enabled" or any other drop-down option is selected, this is a finding.

3) The registry value for HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings?\\SecureProtocols must be "2688". 

If the "SecureProtocols" DWORD value is not "2688", this is a finding.'
  desc 'fix', 'Open Internet Explorer. From the menu bar, select "Tools". From the "Tools" drop-down menu, select "Internet Options". From the "Internet Options" window, select the "Advanced" tab, from the "Advanced" tab window scroll down to the "Security" category. Place a checkmark in "Use TLS 1.1" and "Use TLS 1.2" check boxes.

Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Advanced Page >> "Turn off Encryption Support" to "Enabled", and select "Use TLS 1.1" and "Use TLS 1.2" from the drop-down box.

Set the registry value for HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings?\\SecureProtocols must to "2688".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42764r20_chk'
  tag severity: 'medium'
  tag gid: 'V-6238'
  tag rid: 'SV-45415r8_rule'
  tag stig_id: 'DTBI014'
  tag gtitle: 'DTBI014- IE TLS Setting'
  tag fix_id: 'F-38812r16_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
