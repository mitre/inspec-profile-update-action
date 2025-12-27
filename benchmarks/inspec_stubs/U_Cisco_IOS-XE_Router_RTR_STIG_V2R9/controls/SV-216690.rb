control 'SV-216690' do
  title 'The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes that do not belong to any customers or the local autonomous system (AS).'
  desc 'Advertisement of routes by an autonomous system for networks that do not belong to any of its customers pulls traffic away from the authorized network. This causes a denial of service (DoS) on the network that allocated the block of addresses and may cause a DoS on the network that is inadvertently advertising it as the originator. It is also possible that a misconfigured or compromised router within the GIG IP core could redistribute Interior Gateway Protocol (IGP) routes into BGP, thereby leaking internal routes.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Verify that a prefix list has been configured containing prefixes belonging to customers as well as the local AS as shown in the example below.

ip prefix-list CE_PREFIX_ADVERTISEMENTS seq 5 permit x.13.1.0/24 le 32
ip prefix-list CE_PREFIX_ADVERTISEMENTS seq 10 permit x.13.2.0/24 le 32
ip prefix-list CE_PREFIX_ADVERTISEMENTS seq 15 permit x.13.3.0/24 le 32
ip prefix-list CE_PREFIX_ADVERTISEMENTS seq 20 permit x.13.4.0/24 le 32
…
…
…
ip prefix-list CE_PREFIX_ADVERTISEMENTS seq 80 deny 0.0.0.0/0 ge 8

Step 2: Verify that the prefix lists has been applied to all CE peers as shown in the example below.

router bgp 64512
 no synchronization
 bgp log-neighbor-changes
 neighbor x.12.4.14 remote-as 64514
 neighbor x.12.4.14 prefix-list CE_PREFIX_ADVERTISEMENTS out
 neighbor x.12.4.16 remote-as 64516
 neighbor x.12.4.16 prefix-list CE_PREFIX_ADVERTISEMENTS out

Note: This check is NA for JRSS systems.

If the router is not configured to reject outbound route advertisements that do not belong to any customers or the local AS, this is a finding.'
  desc 'fix', 'Step 1: Configure a prefix list for containing all customer and local AS prefixes as shown in the example below:

R1(config)#ip prefix-list CE_PREFIX_ADVERTISEMENTS permit x.13.1.0/24 le 32
R1(config)#ip prefix-list CE_PREFIX_ADVERTISEMENTS permit x.13.2.0/24 le 32
R1(config)#ip prefix-list CE_PREFIX_ADVERTISEMENTS permit x.13.3.0/24 le 32
R1(config)#ip prefix-list CE_PREFIX_ADVERTISEMENTS permit x.13.4.0/24 le 32
…
…
…
R1(config)#ip prefix-list CE_PREFIX_ADVERTISEMENTS deny 0.0.0.0/0 ge 8

Step 2: Apply the prefix list filter outbound to each CE neighbor as shown in the example.

R1(config)#router bgp 64512
R1(config-router)#neighbor x.12.4.14 prefix-list CE_PREFIX_ADVERTISEMENTS out
R1(config-router)#neighbor x.12.4.16 prefix-list CE_PREFIX_ADVERTISEMENTS out'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17923r917429_chk'
  tag severity: 'medium'
  tag gid: 'V-216690'
  tag rid: 'SV-216690r917430_rule'
  tag stig_id: 'CISC-RT-000520'
  tag gtitle: 'SRG-NET-000018-RTR-000005'
  tag fix_id: 'F-17921r288016_fix'
  tag 'documentable'
  tag legacy: ['SV-106091', 'V-96953']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
