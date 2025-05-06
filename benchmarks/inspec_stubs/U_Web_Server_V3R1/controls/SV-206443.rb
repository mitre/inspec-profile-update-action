control 'SV-206443' do
  title 'The web server must install security-relevant software updates within the configured time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

The web server will be configured to check for and install security-relevant software updates from an authoritative source within an identified time period from the availability of the update. By default, this time period will be every 24 hours.'
  desc 'check', 'Review the web server documentation and configuration to determine if the web server checks for patches from an authoritative source at least every 30 days.

If there is no timeframe or the timeframe is greater than 30 days, this is a finding.'
  desc 'fix', 'Configure the web server to check for patches and updates from an authoritative source at least every 30 days.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6704r377921_chk'
  tag severity: 'medium'
  tag gid: 'V-206443'
  tag rid: 'SV-206443r855064_rule'
  tag stig_id: 'SRG-APP-000456-WSR-000187'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-6704r377922_fix'
  tag 'documentable'
  tag legacy: ['SV-70287', 'V-56033']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
