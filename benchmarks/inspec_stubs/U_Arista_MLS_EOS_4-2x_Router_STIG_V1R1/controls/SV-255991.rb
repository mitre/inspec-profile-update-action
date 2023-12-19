control 'SV-255991' do
  title 'The Arista BGP router must be configured to reject outbound route advertisements for any prefixes that do not belong to any customers or the local autonomous system (AS).'
  desc 'Advertisement of routes by an autonomous system for networks that do not belong to any of its customers pulls traffic away from the authorized network. This causes a denial of service (DoS) on the network that allocated the block of addresses and may cause a DoS on the network that is inadvertently advertising it as the originator. It is also possible that a misconfigured or compromised router within the GIG IP core could redistribute IGP routes into BGP, thereby leaking internal routes.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone. 

Review the Arista router configuration to verify a filter is defined to only advertise routes for prefixes that belong to any customers or the local AS.

The prefix filter must be referenced outbound on the appropriate BGP neighbor statements.

Step 1: Verify the prefix list is configured on the router and is accepting only prefixes belonging to customers or the local AS prefix (10.12.0.0/16). To verify IP prefix lists are configured, execute the command "show ip prefix-list".

ip prefix-list ADVERTISE_ROUTES
   seq 10 permit 10.12.0.0/16
   seq 20 deny 10.17.0.0/16
   seq 30 deny 10.23.0.0/16
   seq 40 deny 10.47.0.0/16
   seq 50 deny 10.59.0.0/16
   seq 100 deny 0.0.0.0/0 le 32

Step 2: Verify in the BGP configuration that the filter is applied outbound for each customer to the appropriate BGP neighbor. To verify the BGP config and verify the prefix is applied, execute the command "show run | section router bgp".

router bgp 65001     
 neighbor 100.2.1.1 prefix-list ADVERTISE_ROUTES out

If the Arista router is not configured to reject outbound route advertisements that do not belong to any customers or the local AS, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone. 

Configure all Arista eBGP routers to filter outbound route advertisements for prefixes that are not allocated to or belong to any customer or the local AS.

Configure the Arista router to deny outbound route advertisements for any prefix belonging to the local AS Boundary.

Step 1: Configure the prefix lists.

LEAF-1A(config)#ip prefix-list ADVERTISE_ROUTES
LEAF-1A(config-ip-pfx)#seq 10 permit 10.12.0.0/16
LEAF-1A(config-ip-pfx)#seq 20 deny 10.17.0.0/16
LEAF-1A(config-ip-pfx)#seq 30 deny 10.23.0.0/16
LEAF-1A(config-ip-pfx)#seq 40 deny 10.47.0.0/16
LEAF-1A(config-ip-pfx)#seq 50 deny 10.59.0.0/16
LEAF-1A(config-ip-pfx)#seq 100 deny 0.0.0.0/0 le 32

Step 2: Configure the prefix lists outbound to the appropriate BGP neighbor.

LEAF-1A(config)#router bgp 65001     
LEAF-1A(config-router-bgp)#neighbor 100.2.1.1 prefix-list ADVERTISE_ROUTES out'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59667r882313_chk'
  tag severity: 'medium'
  tag gid: 'V-255991'
  tag rid: 'SV-255991r882315_rule'
  tag stig_id: 'ARST-RT-000050'
  tag gtitle: 'SRG-NET-000018-RTR-000005'
  tag fix_id: 'F-59610r882314_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
