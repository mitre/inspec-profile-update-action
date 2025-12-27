control 'SV-250541' do
  title 'Allow Fallback to SSL 3.0 (Internet Explorer) must be disabled.'
  desc 'This parameter ensures only DoD-approved ciphers and algorithms are enabled for use by the web browser by blocking an insecure fallback to SSL when TLS 1.0 or greater fails.

'
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> "Allow fallback to SSL 3.0 (Internet Explorer)" must be "Enabled", and "No Sites" selected from the drop-down box. If "Allow fallback to SSL 3.0 (Internet Explorer)" is not "Enabled" or any other drop-down option is selected, this is a finding. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings. 

Criteria: If the value "EnableSSL3Fallback" is REG_DWORD=0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> "Allow fallback to SSL 3.0 (Internet Explorer)" to "Enabled", and select "No Sites" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-53976r799947_chk'
  tag severity: 'medium'
  tag gid: 'V-250541'
  tag rid: 'SV-250541r799949_rule'
  tag stig_id: 'DTBI1100-IE11'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-53930r799948_fix'
  tag satisfies: ['SRG-APP-000514', 'SRG-APP-000555', 'SRG-APP-000625', 'SRG-APP-000630', 'SRG-APP-000635']
  tag 'documentable'
  tag legacy: ['SV-79219', 'V-64729']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
