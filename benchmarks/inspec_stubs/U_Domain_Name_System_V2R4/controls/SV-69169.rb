control 'SV-69169' do
  title 'The DNS implementation must ensure each NS record in a zone file points to an active name server authoritative for the domain specified in that record.'
  desc "Poorly constructed NS records pose a security risk because they create conditions under which an adversary might be able to provide the missing authoritative name services that are improperly specified in the zone file. The adversary could issue bogus responses to queries that clients would accept because they learned of the adversary's name server from a valid authoritative name server, one that need not be compromised for this attack to be successful. The list of slave servers must remain current within 72 hours of any changes to the zone architecture that would affect the list of slaves. If a slave server has been retired or is not operational but remains on the list, then an adversary might have a greater opportunity to impersonate that slave without detection, rather than if the slave were actually online. For example, the adversary may be able to spoof the retired slave's IP address without an IP address conflict, which would not be likely to occur if the true slave were active."
  desc 'check', "Review the zone file's configuration and confirm that each NS record points to an active name server authoritative for the domain. If this is not the case, this is a finding."
  desc 'fix', 'Remove any NS record in a zone file that does not point to an active name server authoritative for the domain specified in that record.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55549r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54923'
  tag rid: 'SV-69169r1_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000085'
  tag gtitle: 'SRG-APP-000516-DNS-000085'
  tag fix_id: 'F-59785r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
