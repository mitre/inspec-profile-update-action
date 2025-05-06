control 'SV-223173' do
  title 'Cryptomining protection must be enabled.'
  desc 'The Content Blocking/Tracking Protection feature stops Firefox from loading content from malicious sites. The content might be a script or an image, for example. If a site is on one of the tracker lists you set Firefox to use, then the fingerprinting script (or other tracking script/image) will not be loaded from that site.

Cryptomining scripts use your computer’s central processing unit (CPU) to invisibly mine cryptocurrency.'
  desc 'check', 'Type "about:config" in the address bar, verify that the preference name “privacy.trackingprotection.cryptomining.enabled" is set to “true” and locked. 

Criteria: If the parameter is set incorrectly, then this is a finding. If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference “privacy.trackingprotection.cryptomining.enabled" is set and locked to the value of “true”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24846r531336_chk'
  tag severity: 'medium'
  tag gid: 'V-223173'
  tag rid: 'SV-223173r612236_rule'
  tag stig_id: 'DTBF215'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24834r531337_fix'
  tag 'documentable'
  tag legacy: ['SV-111843', 'V-102881']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
