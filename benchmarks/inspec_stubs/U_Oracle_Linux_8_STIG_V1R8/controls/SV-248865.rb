control 'SV-248865' do
  title 'A firewall must be able to protect against or limit the effects of denial-of-service (DoS) attacks by ensuring OL 8 can implement rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 
 
This requirement addresses the configuration of OL 8 to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exists to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks. 
 
Since version 0.6.0, "firewalld" has incorporated "nftables" as its backend support. Using the limit statement in "nftables" can help to mitigate DoS attacks.

'
  desc 'check', 'Verify "nftables" is configured to allow rate limits on any connection to the system with the following command. 
 
Verify "firewalld" has "nftables" set as the default backend: 
 
$ sudo grep -i firewallbackend /etc/firewalld/firewalld.conf 
 
# FirewallBackend 
FirewallBackend=nftables 
 
If the "nftables" is not set as the "firewallbackend" default, this is a finding.'
  desc 'fix', 'Configure "nftables" to be the default "firewallbackend" for "firewalld" by adding or editing the following line in "/etc/firewalld/firewalld.conf": 
 
FirewallBackend=nftables 
 
Establish rate-limiting rules based on organization-defined types of DoS attacks on impacted network interfaces.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52299r780159_chk'
  tag severity: 'medium'
  tag gid: 'V-248865'
  tag rid: 'SV-248865r902788_rule'
  tag stig_id: 'OL08-00-040150'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-52253r902787_fix'
  tag satisfies: ['SRG-OS-000142-GPOS-00071', 'SRG-OS-000298-GPOS-00116', 'SRG-OS-000420-GPOS-00186']
  tag 'documentable'
  tag cci: ['CCI-001095', 'CCI-002322', 'CCI-002385']
  tag nist: ['SC-5 (2)', 'AC-17 (9)', 'SC-5 a']
end
