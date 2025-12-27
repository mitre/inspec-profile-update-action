control 'SV-237144' do
  title 'ColdFusion must control remote access to Exposed Services.'
  desc 'ColdFusion exposes many existing services as web services.  These services, such as cfpdf, cfmail, and cfpop, can be accessed by users and applications written in other languages and technologies than ColdFusion CFML.  To invoke the services, the client must be on the allowed IP list and have a user account with the proper privileges to the exposed services.  Exposing these services expands the security risk and potential for compromise of the ColdFusion application server.  If a need arises for these services, then the list of allowed IP addresses must be specified and limited to only those requiring access.'
  desc 'check', 'Within the Administrator Console, navigate to the "Allowed IP Addresses" page under the "Security" menu.  If there are any entries in the "Allowed IP Addresses for Exposed Services" section, validate with the SA that the IP addresses and subnets specified require access.

If any of the IP addresses or subnets specified do not require access, this is a finding.'
  desc 'fix', 'Navigate to the "Allowed IP Addresses" page under the "Security" menu.  Remove all entries from the list under the "Allowed IP Addresses for Exposed Services" section that do not require access to ColdFusion services.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40363r641525_chk'
  tag severity: 'medium'
  tag gid: 'V-237144'
  tag rid: 'SV-237144r641527_rule'
  tag stig_id: 'CF11-01-000017'
  tag gtitle: 'SRG-APP-000315-AS-000094'
  tag fix_id: 'F-40326r641526_fix'
  tag 'documentable'
  tag legacy: ['SV-76851', 'V-62361']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
