control 'SV-250540' do
  title 'Turn off Encryption Support must be enabled.'
  desc "This parameter ensures only DoD-approved ciphers and algorithms are enabled for use by the web browser by allowing you to turn on/off support for TLS and SSL. TLS is a protocol for protecting communications between the browser and the target server. When the browser attempts to set up a protected communication with the target server, the browser and server negotiate which protocol and version to use. The browser and server attempt to match each other's list of supported protocols and versions and pick the most preferred match.

"
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Advanced Page >> "Turn off Encryption Support" must be "Enabled".

Verify the only option selected is "Only use TLS 1.2" from the drop-down box.

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings!SecureProtocols.

Criteria: If the value for "SecureProtocols" is not REG_DWORD = "2048", this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Advanced Page >> "Turn off Encryption Support" to "Enabled".

Select only "Only use TLS 1.2" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-53975r804976_chk'
  tag severity: 'medium'
  tag gid: 'V-250540'
  tag rid: 'SV-250540r804978_rule'
  tag stig_id: 'DTBI014-IE11'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-53929r804977_fix'
  tag satisfies: ['SRG-APP-000514', 'SRG-APP-000555', 'SRG-APP-000625', 'SRG-APP-000630', 'SRG-APP-000635']
  tag 'documentable'
  tag legacy: ['SV-59337', 'V-46473']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
