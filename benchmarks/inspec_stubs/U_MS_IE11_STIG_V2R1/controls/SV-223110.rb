control 'SV-223110' do
  title 'Internet Explorer Processes for Zone Elevation must be enforced (Reserved).'
  desc 'Internet Explorer places restrictions on each web page it opens that are dependent upon the location of the web page (such as Internet Zone, Intranet Zone, or Local Machine Zone). Web pages on a local computer have the fewest security restrictions and reside in the Local Machine Zone, which makes the Local Machine Security Zone a prime target for malicious attackers. If you enable this policy setting, any zone can be protected from zone elevation by Internet Explorer processes. This approach stops content running in one zone from gaining the elevated privileges of another zone. If you disable this policy setting, no zone receives such protection from Internet Explorer processes. Because of the severity and relative frequency of zone elevation attacks, this guide recommends that you configure this setting as "Enabled" in all environments.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation -> 'Internet Explorer Processes' must be 'Enabled'.  Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION Criteria: If the value "(Reserved)" is REG_SZ = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation -> 'Internet Explorer Processes' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24783r428880_chk'
  tag severity: 'medium'
  tag gid: 'V-223110'
  tag rid: 'SV-223110r428882_rule'
  tag stig_id: 'DTBI610-IE11'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-24771r428881_fix'
  tag 'documentable'
  tag legacy: ['SV-59591', 'V-46727']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
