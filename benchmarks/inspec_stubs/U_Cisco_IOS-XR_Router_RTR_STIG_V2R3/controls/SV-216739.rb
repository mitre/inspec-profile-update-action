control 'SV-216739' do
  title 'The Cisco router must be configured to authenticate all routing protocol messages using NIST-validated FIPS 198-1 message authentication code algorithm.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

Since MD5 is vulnerable to "birthday" attacks and may be compromised, routing protocol authentication must use FIPS 140-2 validated algorithms and modules to encrypt the authentication key. This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the router configuration to verify it is using a NIST-validated FIPS 198-1 message authentication code algorithm to authenticate routing protocol messages.

key chain BGP_KEY_CHAIN
 key 1
  accept-lifetime 01:00:00 january 01 2019 01:00:00 april 01 2019
  key-string password xxxxxxxxxxxxxxxx
  send-lifetime 01:00:00 january 01 2019 01:00:00 april 01 2019
  cryptographic-algorithm HMAC-SHA1-12
 !
 key 2
  accept-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019
  key-string password xxxxxxxxxxxxxxx
  send-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019
  cryptographic-algorithm HMAC-SHA1-12
 !

Note: OSPF, RIP, EIGRP, and IS-IS only support MD5.

If a NIST-validated FIPS 198-1 message authentication code algorithm is not being used to authenticate routing protocol messages, this is a finding.'
  desc 'fix', 'Configure routing protocol authentication to use a NIST-validated FIPS  198-1 message authentication code algorithm as shown in the example.

RP/0/0/CPU0:R2(config)#key chain BGP_KEY_CHAIN
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN)#key 1
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#accept-lifetime 01:00:00 jan 01 2019 01:00:00 april 01 2019
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#key-string password xxxxxxxxxxx
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#send-lifetime 01:00:00 jan 01 2019 01:00:00 april 01 2019
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#cryptographic-algorithm hmac-sha1-12
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#key 2
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#accept-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#key-string password xxxxxxxxxxxxxxxx
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#send-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019 
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#cryptographic-algorithm hmac-sha1-12
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17971r288609_chk'
  tag severity: 'medium'
  tag gid: 'V-216739'
  tag rid: 'SV-216739r531087_rule'
  tag stig_id: 'CISC-RT-000050'
  tag gtitle: 'SRG-NET-000168-RTR-000078'
  tag fix_id: 'F-17969r288610_fix'
  tag 'documentable'
  tag legacy: ['SV-105823', 'V-96685']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
