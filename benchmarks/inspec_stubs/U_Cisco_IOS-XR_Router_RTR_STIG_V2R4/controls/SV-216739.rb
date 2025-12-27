control 'SV-216739' do
  title 'The Cisco router must be configured to enable routing protocol authentication using FIPS 198-1 algorithms with keys not exceeding 180 days of lifetime.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication using FIPS 198-1 algorithms for routing updates.
If the keys used for authentication are guessed, the malicious user could create havoc within the network by advertising incorrect routes and redirecting traffic. Some routing protocols allow the use of key chains for authentication. A key chain is a set of keys that is used in succession, with each having a lifetime of no more than 180 days. Changing the keys frequently reduces the risk of them eventually being guessed. If a time period occurs during which no key is activated, neighbor authentication cannot occur, and therefore routing updates will fail.)
  desc 'check', 'Review the router configuration using the configuration examples below for BGP and OSPF.

EIGRP, RIP, and IS-IS only support MD5 and will incur a permanent finding for those protocols.

Note: The 180-day key lifetime is Not Applicable for the DODIN Backbone. The remainder of the requirement still applies.

Verify that neighbor router authentication is enabled for all routing protocols. If neighbor authentication is not enabled this is a finding.

Verify that authentication is configured to use FIPS 198-1 message authentication algorithms. If the routing protocol authentication is not configured to use FIPS 198-1 algorithms this is a finding.

Verify that the protocol key lifetime is configured to not exceed 180 days. If any protocol key lifetime is configured to exceed 180 days this is a finding.

BGP Example:

key chain <KEY-CHAIN-NAME> 
 key <KEY-ID>
 send-id <ID>
 recv-id <ID>
 cryptographic-algorithm hmac-sha256
 key-string <KEY>
 accept-lifetime 00:00:00 Jan 1 2022 duration 180
 send-lifetime 00:00:00 Jan 1 2022 duration 180 
!
tcp ao 
 keychain BGP_KEY_CHAIN
  key <KEY-ID> SendID <ID> ReceiveID <ID>
!
!
router bgp <ASN> 
 neighbor X.X.X.X
  remote-as <ASN>
  ao BGP_KEY_CHAIN
address-family ipv4 unicast
!

Note: TCP-AO is used to replace MD5 in BGP authentication. 

OSPF Example:

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
router ospf 1
area 0
authentication message-digest keychain OSPF_KEY_CHAIN'
  desc 'fix', 'Configure routing protocol authentication to use a NIST-validated FIPS 198-1 message authentication code algorithm with keys not exceeding 180 days of lifetime as shown in the examples.

BGP Example:

Step 1: Configure a keychain using a FIPS 198-1 algorithm with a key duration not exceeding 180 days.

key chain <KEY-CHAIN-NAME> 
 key <KEY-ID>
 send-id <ID>
 recv-id <ID>
 cryptographic-algorithm hmac-sha256
 key-string <KEY>
 accept-lifetime 00:00:00 Jan 1 2022 duration 180
 send-lifetime 00:00:00 Jan 1 2022 duration 180 

Step 2: Configure BGP autonomous system to use the keychain for authentication.

tcp ao 
 keychain BGP_KEY_CHAIN
  key <KEY-ID> SendID <ID> ReceiveID <ID>
!
!
router bgp <ASN> 
 neighbor X.X.X.X
  remote-as <ASN>
  ao BGP_KEY_CHAIN
address-family ipv4 unicast

OSPF Example:

Step 1: Configure a keychain using a FIPS 198-1 algorithm with a key duration not exceeding 180 days.

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

Step 2: Configure OSPF to use the keychain for authentication.

router ospf 1
area 0
authentication message-digest keychain OSPF_KEY_CHAIN'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17971r929059_chk'
  tag severity: 'medium'
  tag gid: 'V-216739'
  tag rid: 'SV-216739r929061_rule'
  tag stig_id: 'CISC-RT-000050'
  tag gtitle: 'SRG-NET-000168-RTR-000078'
  tag fix_id: 'F-17969r929060_fix'
  tag 'documentable'
  tag legacy: ['SV-105823', 'V-96685']
  tag cci: ['CCI-000803', 'CCI-002205']
  tag nist: ['IA-7', 'AC-4 (17)']
end
