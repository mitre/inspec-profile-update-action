control 'SV-235760' do
  title 'Site isolation for every site must be enabled.'
  desc 'The "SitePerProcess" policy can be used to prevent users from opting out of the default behavior of isolating all sites. The "IsolateOrigins" policy can be used to isolate additional, finer-grained origins.

Enabling this policy prevents users from opting out of the default behavior where each site runs in its own process.

If this policy is not disabled or configured, a user can opt out of site isolation (e.g., by using "Disable site isolation" entry in edge://flags.) Disabling the policy or not configuring the policy does not turn off Site Isolation.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable site isolation for every site" must be set to "enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "SitePerProcess" is not set to "REG_DWORD = 1", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Enable site isolation for every site" to "enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38979r626476_chk'
  tag severity: 'medium'
  tag gid: 'V-235760'
  tag rid: 'SV-235760r626523_rule'
  tag stig_id: 'EDGE-00-000047'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38942r626477_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
