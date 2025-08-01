control 'SV-223172' do
  title 'Fingerprinting protection must be enabled.'
  desc 'The Content Blocking/Tracking Protection feature stops Firefox from loading content from malicious sites. The content might be a script or an image, for example. If a site is on one of the tracker lists you set Firefox to use, then the fingerprinting script (or other tracking script/image) will not be loaded from that site.

Fingerprinting scripts collect information about your browser and device configuration, such as your operating system, screen resolution, and other settings. By compiling these pieces of data, fingerprinters create a unique profile of you that can be used to track you around the Web.'
  desc 'check', 'Type "about:config" in the address bar, verify that the preference name “privacy.trackingprotection.fingerprinting.enabled" is set to “true” and locked. 

Criteria: If the parameter is set incorrectly, then this is a finding. If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference “privacy.trackingprotection.fingerprinting.enabled" is set and locked to the value of “true”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24845r531333_chk'
  tag severity: 'medium'
  tag gid: 'V-223172'
  tag rid: 'SV-223172r612236_rule'
  tag stig_id: 'DTBF210'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24833r531334_fix'
  tag 'documentable'
  tag legacy: ['SV-111841', 'V-102879']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
