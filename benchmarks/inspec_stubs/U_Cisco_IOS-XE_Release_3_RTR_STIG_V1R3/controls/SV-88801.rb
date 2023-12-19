control 'SV-88801' do
  title 'The Cisco IOS XE router must encrypt all methods of configured authentication for routing protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network, or merely used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack. 

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and Multicast-related protocols.)
  desc 'check', 'Review the configuration of the Cisco IOS XE router. 

Verify that an encrypted HMAC authentication is being used for all routing protocols as shown in the following configuration examples:

key chain OSPF_KEY
key 1
  key-string OSPFKEY
   cryptographic-algorithm hmac-sha-1
!
interface GigabitEthernet3
ip address 1.1.35.3 255.255.255.0
ip ospf authentication key-chain OSPF_KEY
-------------------------------------------
key chain EIGRP_KEY
key 1
  key-string EIGRPKEY
!
interface GigabitEthernet3
ip address 1.1.35.3 255.255.255.0
ip authentication mode eigrp 22 md5
ip authentication key-chain eigrp 22 EIGRP_KEY
----------------------------------------
key chain ISIS_KEY
key 1
  key-string ISISKEY
!
interface GigabitEthernet3
ip address 1.1.35.3 255.255.255.0
ip router isis 
 isis authentication mode md5
 isis authentication key-chain ISIS_KEY
---------------------------------------------
router bgp 44
neighbor 1.1.1.1 remote-as 44
neighbor 1.1.1.1 password xxxxx
---------------------------------------------

If not all routing protocols are configured to authenticate all routing protocol messages using an encrypted HMAC, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to use an encrypted HMAC authentication for all routing protocols.'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74213r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74127'
  tag rid: 'SV-88801r2_rule'
  tag stig_id: 'CISR-RT-000016'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag fix_id: 'F-80669r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
