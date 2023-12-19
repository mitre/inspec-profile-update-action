control 'SV-79207' do
  title 'Prevent ignoring certificate errors option must be enabled.'
  desc 'This policy setting prevents the user from ignoring Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificate errors that interrupt browsing (such as “expired”, “revoked”, or “name mismatch” errors) in Internet Explorer. If you enable this policy setting, the user cannot continue browsing. If you disable or do not configure this policy setting, the user can choose to ignore certificate errors and continue browsing.'
  desc 'check', 'The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> ”Prevent ignoring certificate errors” must be ”Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings. 

Criteria: If the value "PreventIgnoreCertErrors" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> ”Prevent ignoring certificate errors” to ”Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-65459r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64717'
  tag rid: 'SV-79207r2_rule'
  tag stig_id: 'DTBI1075-IE11'
  tag gtitle: 'DTBI1075-IE11-Prevent Ignoring Certificate Errors'
  tag fix_id: 'F-70647r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
