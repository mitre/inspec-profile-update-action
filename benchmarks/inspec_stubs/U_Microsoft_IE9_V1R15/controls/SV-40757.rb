control 'SV-40757' do
  title 'Browser Geolocation functionality must be disallowed.'
  desc 'This setting has a small impact on user privacy because users may unknowingly allow their browser to share location data with web sites that they visit.  The value of enabling this setting is diminished due to the fact that malicious web sites can learn a great deal about the location of a user merely by analyzing their IP address.  If you enable this policy setting, browser geolocation support will be turned off. If you disable this policy setting, browser geolocation will be turned on.  If you do not configure this setting, browser geolocation support can be turned on or off in Internet Options on the Privacy Tab.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Disable Browser Geolocation" must be “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Geolocation 

Criteria: If the value PolicyDisableGeolocation  is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Disable Browser Geolocation" to “Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39502r2_chk'
  tag severity: 'medium'
  tag gid: 'V-30775'
  tag rid: 'SV-40757r1_rule'
  tag stig_id: 'DTBI755'
  tag gtitle: 'DTBI755 - Browser Geolocation Functionality'
  tag fix_id: 'F-34708r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
