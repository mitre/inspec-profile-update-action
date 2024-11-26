control 'SV-221120' do
  title 'The Cisco PE switch providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information using a FIPS-approved message authentication code algorithm.'
  desc 'LDP provides the signaling required for setting up and tearing down pseudowires (virtual circuits used to transport Layer 2 frames) across an MPLS IP core network. Using a targeted LDP session, each PE switch advertises a virtual circuit label mapping that is used as part of the label stack imposed on the frames by the ingress PE switch during packet forwarding. Authentication provides protection against spoofed TCP segments that can be introduced into the LDP sessions.'
  desc 'check', 'The Cisco switch is not compliant with this requirement; hence, it is a finding. However, the severity level can be downgraded to a category 3 if the switch is configured to authenticate targeted LDP sessions using MD5 as shown in the configuration example below:

Step 1: Verify that LDP neighbors are authenticating session, advertisement, and notification messages as shown in the example below:

mpls ldp configurations
 password required for LDP_NBR1
 password option 1 for LDP_NBR1 key-chain LDP_KEY
 password required for LDP_NBR2
 password option 1 for LDP_NBR2 key-chain LDP_KEY

Step 2: Verify that the neighbors identified in step 1 have the correct prefix.

ip prefix-list LDP_NBR1 permit 10.1.22.2/32
ip prefix-list LDP_NBR2 permit 10.1.12.4/32

If the switch is not configured to authenticate targeted LDP sessions using MD5, this is a finding. The finding will remain as a CAT II.'
  desc 'fix', 'The severity level can be downgraded to a category 3 if the switch is configured to authenticate targeted LDP sessions using MD5 as shown in the example below:

Step 1: Configure a key chain for LDP sessions.

 SW1(config)# key chain LDP_KEY
SW1(config-keychain)# key 1
SW1(config-keychain-key)# key-string xxxxxxxxxxxx
SW1(config-keychain-key)# send-lifetime 00:00:00 Oct 1 2019 23:59:59 Dec 31 2019
SW1(config-keychain-key)# accept-lifetime 00:00:00 Oct 1 2019 01:05:00 Jan 1 2020
SW1(config-keychain-key)# exit
SW1(config-keychain)# exit

Step 2: Configure a prefix lists to identify LDP neighbors.

SW1(config)# ip prefix-list LDP_NBR1 permit 10.1.22.2/32
SW1(config)# ip prefix-list LDP_NBR2 permit 10.1.12.4/32

Step 3: Apply the key chain to the LDP neighbors.

SW1 (config)# mpls ldp configurations
SW1 (config-ldp)# password required for LDP_NBR1
SW1 (config-ldp)# password option 1 for LDP_NBR1 key-chain LDP_KEY
SW1 (config-ldp)# password required for LDP_NBR2
SW1 (config-ldp)# password option 1 for LDP_NBR2 key-chain LDP_KEY
SW1 (config-ldp)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22835r409849_chk'
  tag severity: 'medium'
  tag gid: 'V-221120'
  tag rid: 'SV-221120r856631_rule'
  tag stig_id: 'CISC-RT-000660'
  tag gtitle: 'SRG-NET-000343-RTR-000001'
  tag fix_id: 'F-22824r409850_fix'
  tag 'documentable'
  tag legacy: ['SV-111059', 'V-101955']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
