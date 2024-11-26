control 'SV-205246' do
  title 'The IP address for hidden master authoritative name servers must not appear in the name servers set in the zone database.'
  desc 'A hidden master authoritative server is an authoritative DNS server whose IP address does not appear in the name server set for a zone.  All of the name servers that do appear in the zone database as designated name servers get their zone data from the hidden master via a zone transfer request. In effect, all visible name servers are actually secondary slave servers. This prevents potential attackers from targeting the master name server because its IP address may not appear in the zone database.'
  desc 'check', 'Check the DNS documentation to determine if a hidden master authoritative name server is being used. If a hidden master authoritative name server is being used, check the NS records for all zones for which that hidden name server is authoritative and confirm there is not any NS record for that hidden name server.

If any zone for which a hidden name server is authoritative has an NS record for that hidden name server, this is a finding.
If the DNS implementation does not include any hidden name servers, this is not applicable.'
  desc 'fix', "Remove, from all zones' configuration files, any NS RRs for hidden name servers."
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5513r392651_chk'
  tag severity: 'medium'
  tag gid: 'V-205246'
  tag rid: 'SV-205246r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000108'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5513r392652_fix'
  tag 'documentable'
  tag legacy: ['SV-69199', 'V-54953']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
