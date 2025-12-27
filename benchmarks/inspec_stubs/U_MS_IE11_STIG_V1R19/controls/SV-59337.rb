control 'SV-59337' do
  title 'Turn off Encryption Support must be enabled.'
  desc "This parameter ensures only DoD-approved ciphers and algorithms are enabled for use by the web browser by allowing you to turn on/off support for TLS and SSL. TLS is a protocol for protecting communications between the browser and the target server. When the browser attempts to set up a protected communication with the target server, the browser and server negotiate which protocol and version to use. The browser and server attempt to match each other's list of supported protocols and versions and pick the most preferred match.."
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Advanced Page >> "Turn off Encryption Support" must be "Enabled".

Verify the only options selected are "Use TLS 1.1" and "Use TLS 1.2" from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings!SecureProtocols.

Criteria: If the value for "SecureProtocols" is not REG_DWORD = "2560", this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Advanced Page >> "Turn off Encryption Support" to "Enabled".

Select only "Use TLS 1.1" and "Use TLS 1.2" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49683r19_chk'
  tag severity: 'medium'
  tag gid: 'V-46473'
  tag rid: 'SV-59337r8_rule'
  tag stig_id: 'DTBI014-IE11'
  tag gtitle: 'DTBI014-IE11-TLS setting'
  tag fix_id: 'F-50263r18_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
