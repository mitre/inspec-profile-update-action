control 'SV-220423' do
  title 'The Cisco switch must be configured to authenticate all routing protocol messages using NIST-validated FIPS 198-1 message authentication code algorithm.'
  desc %q(A rogue switch could send a fictitious routing update to convince a site's perimeter switch to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. 

This is known as a "traffic attraction attack" and is prevented by configuring neighbor switch authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack. 

Since MD5 is vulnerable to "birthday" attacks and may be compromised, routing protocol authentication must use FIPS 140-2 validated algorithms and modules to encrypt the authentication key. This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the switch configuration to verify it is using a NIST-validated FIPS 198-1 message authentication code algorithm to authenticate routing protocol messages. 

OSPF example: 

key chain OSPF_KEY_CHAIN 
 key 1 
 key-string xxxxxxx 
 send-lifetime 00:00:00 Jan 1 2018 23:59:59 Mar 31 2018 
 accept-lifetime 00:00:00 Jan 1 2018 01:05:00 Apr 1 2018 
 cryptographic-algorithm hmac-sha-256 
 key 2 
 key-string yyyyyyy 
 send-lifetime 00:00:00 Apr 1 2018 23:59:59 Jun 30 2018 
 accept-lifetime 23:55:00 Mar 31 2018 01:05:00 Jul 1 2018 
 cryptographic-algorithm hmac-sha-256 
… 
… 
… 
interface GigabitEthernet0/1 
 no switchport 
 ip address x.x.x.x 255.255.255.0 
 ip ospf authentication key-chain OSPF_KEY_CHAIN 

If a NIST-validated FIPS 198-1 message authentication code algorithm is not being used to authenticate routing protocol messages, this is a finding.'
  desc 'fix', 'Configure routing protocol authentication to use a NIST-validated FIPS 198-1 message authentication code algorithm as shown in the example below: 

SW1(config)#key chain OSPF_KEY_CHAIN 
SW1(config-keychain)#key 1 
SW1(config-keychain-key)#key-string xxxxxx 
SW1(config-keychain-key)#send-lifetime 00:00:00 Jan 1 2018 23:59:59 Mar 31 2018 
SW1(config-keychain-key)#accept-lifetime 00:00:00 Jan 1 2018 01:05:00 Apr 1 2018 
SW1(config-keychain-key)#cryptographic-algorithm hmac-sha-256 
SW1(config-keychain-key)#exit 
SW1(config-keychain)#key 2 
SW1(config-keychain-key)#key-string yyyyyyy 
SW1(config-keychain-key)#send-lifetime 00:00:00 Apr 1 2018 23:59:59 Jun 30 2018 
SW1(config-keychain-key)#accept-lifetime 23:55:00 Mar 31 2018 01:05:00 Jul 1 2018 
SW1(config-keychain-key)#cryptographic-algorithm hmac-sha-256 
SW1(config-keychain-key)#end 
SW1(config)#interface GigabitEthernet0/2 
SW1(config-if)#ip ospf authentication key-chain OSPF_KEY_CHAIN'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22138r508357_chk'
  tag severity: 'medium'
  tag gid: 'V-220423'
  tag rid: 'SV-220423r622190_rule'
  tag stig_id: 'CISC-RT-000050'
  tag gtitle: 'SRG-NET-000168-RTR-000078'
  tag fix_id: 'F-22127r508358_fix'
  tag 'documentable'
  tag legacy: ['SV-110693', 'V-101589']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
