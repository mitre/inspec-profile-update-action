control 'SV-79201' do
  title 'Prevent bypassing SmartScreen Filter warnings must be enabled.'
  desc 'This policy setting determines whether the user can bypass warnings from SmartScreen Filter. SmartScreen Filter prevents the user from browsing to or downloading from sites that are known to host malicious content. SmartScreen Filter also prevents the execution of files that are known to be malicious. If you enable this policy setting, SmartScreen Filter warnings block the user. If you disable or do not configure this policy setting, the user can bypass SmartScreen Filter warnings.'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> ”Prevent bypassing SmartScreen Filter warnings” must be ”Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\PhishingFilter. 

Criteria: If the value "PreventOverride" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> ”Prevent bypassing SmartScreen Filter warnings” to ”Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-65453r3_chk'
  tag severity: 'medium'
  tag gid: 'V-64711'
  tag rid: 'SV-79201r2_rule'
  tag stig_id: 'DTBI1060-IE11'
  tag gtitle: 'DTBI1060-IE11-Managing SmartScreen Filter Warnings'
  tag fix_id: 'F-70641r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
