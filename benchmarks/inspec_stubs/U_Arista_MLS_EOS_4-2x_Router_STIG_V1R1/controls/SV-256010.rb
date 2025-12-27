control 'SV-256010' do
  title 'The Arista router must be configured to authenticate all routing protocol messages using NIST-validated FIPS 198-1 message authentication code algorithm.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

Since MD5 is vulnerable to "birthday" attacks and may be compromised, routing protocol authentication must use FIPS 198-1 validated algorithms and modules to encrypt the authentication key. This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.

)
  desc 'check', 'Review the Arista router configuration to verify it is using a NIST-validated FIPS 198-1 message authentication code algorithm to authenticate routing protocol messages.

OSPFv2 Example:

Verify the Message-Digest authentication configuration on the interface for OSPF with the following command:

sh run int ethernet YY

interface Eth12
 ip ospf authentication message-digest
 ip ospf message-digest-key 23 sha256 0 arista123

If MD5 is present in the output, this is a finding.

BGP Example:

Step 1: Arista router must verify the system clock is set to the correct date/time zone and clock source as this will affect the key lifetimes.

router#show clock
Wed Oct 5 14:25:53 2022
Timezone: US/Pacific
Clock source: NTP server (192.168.10.25)

If the clock is incorrect, this is a finding. 

Step 2: Arista router must verify the management security profile is configured and the session shared-secrets Lifetime durations are specified for the required rotation order and must not exceed 180 days.

router#sh man sec session shared-secret profile BGP-SHA1
Profile: BGP-SHA1

Current receive secret: ID: 5, Expires: December 05 2022, 14:34 UTC
Current transmit secret: ID: 5, Expires: December 05 2022, 14:34 UTC

Receive secret rotation order: 5, 10, 15
Transmit secret rotation order: 5, 10, 15

Secrets:
   ID 15
      Secret: $1c$rcKS3MQ9sre00iXfxDVMEg==
      Receive lifetime: March 05 2023, 14:34 UTC to infinite
      Transmit lifetime: March 05 2023, 14:34 UTC to infinite
   ID 10
      Secret: $1c$rcKS3MQ9srcBunxwqKkGEw==
      Receive lifetime: December 05 2022, 14:34 UTC to March 05 2023, 14:34 UTC
      Transmit lifetime: December 05 2022, 14:34 UTC to March 05 2023, 14:34 UTC
   ID 5
      Secret: $1c$rcKS3MQ9srd9RAMH9iKmPQ==
      Receive lifetime: October 05 2022, 14:34 UTC to December 05 2022, 14:34 UTC
      Transmit lifetime: October 05 2022, 14:34 UTC to December 05 2022, 14:34 UTC

If the management security profile is not configured, this is a finding.

If the key lifetime exceeds 180 days, this is a finding.

Step 3: Arista router must verify the BGP peer group is configured to use the BGP security profile for the configured BGP neighbor peer. BGP Graceful-restart must be configured in the event the peer restarts to allow TCP resets and prevent clearing of traffic keys. Arista router supports graceful-restart restart-time configuration <1-3600> default [300 seconds].

show running-config | section bgp 65000
router bgp 65000
   router-id 10.11.11.11
   graceful-restart restart-time 300
   graceful-restart
   neighbor Peer_Leaf peer group
   neighbor Peer_Leaf remote-as 65000
   neighbor Peer_Leaf next-hop-self
   neighbor Peer_Leaf send-community extended
   neighbor Peer_Leaf maximum-routes 12000
   neighbor Peer_Leaf2 peer group
   neighbor Peer_Leaf2 remote-as 200
   neighbor Peer_Leaf2 next-hop-self
   neighbor Peer_Leaf2 send-community extended
   neighbor Peer_Leaf2 maximum-routes 12000
   neighbor 1.1.1.1 password 7 kEFkx0nsheXsR5ICROtOfB==
   neighbor 1.1.1.1 maximum-routes 12000
   neighbor 2.2.2.2 peer group Peer_Leaf2
   neighbor 2.2.2.2 password shared-secret profile BGP-SHA1 algorithm aes-128-cmac-96
   neighbor 2.2.2.2 maximum-routes 12000
   neighbor 10.11.12.2 peer group Peer_Leaf
   no neighbor 10.11.12.2 route-map out
   redistribute connected route-map loopback

If BGP is not configured to use the security profile, this is a finding.'
  desc 'fix', 'Configure routing protocol authentication to use a NIST-validated FIPS 198-1 message authentication code algorithm.

OSPFv2:

router(config)#interface Eth12
router(config-int-Eth12)#ip ospf authentication message-digest
router(config-int-Eth12)#ip ospf message-digest-key 23 sha256 0 arista123

BGP:

Step 1: The Arista router must configure the system clock, which will affect the valid key for a given profile and should be used with caution.

router(config)#clock set hh:mm:ss  Current time

Step 2: The Arista router must be configured for management security profile <profile_name> and keys for BGP neighbor sessions.

router(config)#management security
router(config-man-sec)#session shared-secret profile BGP-SHA
router(config-man-sec-sh-sec-profile-BGP-SHA)#secret 5 password1 2022-10-05 14:34:01 2022–12-05 14:34:01
router(config-man-sec-sh-sec-profile-BGP-SHA)#secret 10 password2 2022-12-05 14:34:01 2023-03-05 14:34:01
router(config-man-sec-sh-sec-profile-BGP-SHA)#secret 15 password3 2023-10-05 14:34:01 <not to exceed 180 days>

Step 3: The Arista router must configure the BGP Neighbor to select the profile for use in TCP AO.

router(config)#router bgp 65000
router(config-router-bgp)#neighbor 2.2.2.2 password shared-secret profile BGP-SHA1 algorithm aes-128-cmac-96
router(config-router-bgp)#exit
router(config)#write memory'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59686r882370_chk'
  tag severity: 'medium'
  tag gid: 'V-256010'
  tag rid: 'SV-256010r882372_rule'
  tag stig_id: 'ARST-RT-000280'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag fix_id: 'F-59629r882371_fix'
  tag satisfies: ['SRG-NET-000168-RTR-000077', 'SRG-NET-000168-RTR-000078']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-002205']
  tag nist: ['IA-7', 'AC-4 (17)']
end
