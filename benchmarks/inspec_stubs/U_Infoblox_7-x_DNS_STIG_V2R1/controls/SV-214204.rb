control 'SV-214204' do
  title 'The Infoblox system must ensure each NS record in a zone file points to an active name server authoritative for the domain specified in that record.'
  desc "Poorly constructed NS records pose a security risk because they create conditions under which an adversary might be able to provide the missing authoritative name services that are improperly specified in the zone file. The adversary could issue bogus responses to queries that clients would accept because they learned of the adversary's name server from a valid authoritative name server, one that need not be compromised for this attack to be successful. The list of slave servers must remain current within 72 hours of any changes to the zone architecture that would affect the list of slaves. If a slave server has been retired or is not operational but remains on the list, then an adversary might have a greater opportunity to impersonate that slave without detection, rather than if the slave were actually online. For example, the adversary may be able to spoof the retired slave's IP address without an IP address conflict, which would not be likely to occur if the true slave were active."
  desc 'check', 'For Infoblox Grid Members, log on to the Grid Master.

Navigate to Data Management >> DNS >> Members/Servers tab.

Verify that all assigned members have a status of "Running".
For non-Infoblox systems, review DNS zone data and confirm that all systems external to the Infoblox grid have NS records which point to an active name server authoritative for the domain.

If the Infoblox Grid Members do not have a status of "Running" or non-Infoblox systems do not have NS records pointing to an active name server authoritative for the domain, this is a finding.'
  desc 'fix', 'Use either global search or review of DNS zone data to verify NS configuration.

Remove or update any incorrect NS records or name server configuration.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15419r295875_chk'
  tag severity: 'medium'
  tag gid: 'V-214204'
  tag rid: 'SV-214204r612370_rule'
  tag stig_id: 'IDNS-7X-000730'
  tag gtitle: 'SRG-APP-000516-DNS-000085'
  tag fix_id: 'F-15417r295876_fix'
  tag 'documentable'
  tag legacy: ['SV-83093', 'V-68603']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
