control 'SV-223042' do
  title 'Prevent ignoring certificate errors option must be enabled.'
  desc 'This policy setting prevents the user from ignoring Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificate errors that interrupt browsing (such as “expired”, “revoked”, or “name mismatch” errors) in Internet Explorer. If you enable this policy setting, the user cannot continue browsing. If you disable or do not configure this policy setting, the user can choose to ignore certificate errors and continue browsing.'
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> ”Prevent ignoring certificate errors” must be ”Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings. 

Criteria: If the value "PreventIgnoreCertErrors" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> ”Prevent ignoring certificate errors” to ”Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24715r428676_chk'
  tag severity: 'medium'
  tag gid: 'V-223042'
  tag rid: 'SV-223042r879798_rule'
  tag stig_id: 'DTBI1075-IE11'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-24703r428677_fix'
  tag 'documentable'
  tag legacy: ['SV-79207', 'V-64717']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
