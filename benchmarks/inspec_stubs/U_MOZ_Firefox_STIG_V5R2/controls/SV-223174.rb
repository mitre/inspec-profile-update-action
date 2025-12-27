control 'SV-223174' do
  title 'Enhanced Tracking Protection must be enabled.'
  desc 'Tracking generally refers to content, cookies, or scripts that can collect your browsing data across multiple sites.'
  desc 'check', 'Type "about:config" in the address bar, verify that the preference name “browser.contentblocking.category" is set to “strict” and locked. 

Criteria: If the parameter is set incorrectly, then this is a finding. If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference “browser.contentblocking.category" is set and locked to the value of “strict”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24847r531339_chk'
  tag severity: 'medium'
  tag gid: 'V-223174'
  tag rid: 'SV-223174r612236_rule'
  tag stig_id: 'DTBF220'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24835r531340_fix'
  tag 'documentable'
  tag legacy: ['SV-111845', 'V-102883']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
