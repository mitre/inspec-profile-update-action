control 'SV-45242' do
  title 'Internet Explorer Processes for Zone Elevation must be enforced (Explorer).'
  desc 'Internet Explorer places restrictions on each web page it opens that are dependent upon the location of the web page (such as Internet Zone, Intranet Zone, or Local Machine Zone). Web pages on a local computer have the fewest security restrictions and reside in the Local Machine Zone, which makes the Local Machine Security Zone a prime target for malicious attackers. If you enable this policy setting, any zone can be protected from zone elevation by Internet Explorer processes. This approach stops content running in one zone from gaining the elevated privileges of another zone. If you disable this policy setting, no zone receives such protection from Internet Explorer processes. Because of the severity and relative frequency of zone elevation attacks, this guide recommends configuring this setting as Enabled in all environments.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation -> "Internet Explorer Processes" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_ZONE_ELEVATION 

Criteria: If the value explorer.exe is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation -> "Internet Explorer Processes" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42591r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15569'
  tag rid: 'SV-45242r1_rule'
  tag stig_id: 'DTBI612'
  tag gtitle: 'DTBI612 - Zone Elevation - Explorer'
  tag fix_id: 'F-38638r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
