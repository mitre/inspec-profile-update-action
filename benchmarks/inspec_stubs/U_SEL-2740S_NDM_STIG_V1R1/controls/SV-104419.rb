control 'SV-104419' do
  title 'The SEL-2740S must authenticate Network Time Protocol sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Verify NTP packets only traverse on the private network by traffic engineering both the physical path and redundant path between switch and NTP server.

1. Login to the OTSDN Controller with permission Level 3 rights into parent.
2. Go to the Configuration Objects settings page.
3. Review the NTP Server IP addresses in the settings fields.

If the IP addresses are not within the private network, this is a finding.'
  desc 'fix', 'Deploy the NTP server within the private network. Provision both the physical path and redundant path between the switch and NTP server to ensure NTP packets only traverse the private network. Use multilayer packet inspection at each hop of the switches to whitelist only the intended NTP clients and server can communicate to each other.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-93779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94589'
  tag rid: 'SV-104419r2_rule'
  tag stig_id: 'SELS-ND-001025'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-100707r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
