control 'SV-216794' do
  title 'The Cisco PE router providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information using a FIPS-approved message authentication code algorithm.'
  desc 'LDP provides the signaling required for setting up and tearing down pseudowires (virtual circuits used to transport Layer 2 frames) across an MPLS IP core network. Using a targeted LDP session, each PE router advertises a virtual circuit label mapping that is used as part of the label stack imposed on the frames by the ingress PE router during packet forwarding. Authentication provides protection against spoofed TCP segments that can be introduced into the LDP sessions.'
  desc 'check', 'The Cisco router is not compliant with this requirement; hence, it is a finding. However, the severity level can be downgraded to a category 3 if the router is configured to authenticate targeted LDP sessions using MD5 as shown in the configuration example below.

mpls ldp
router-id 10.1.1.2
neighbor 10.1.1.1
  password encrypted xxxxxxxxxxxxxxx
neighbor 10.1.2.1
  password encrypted xxxxxxxxxxxxxxx

If the router is not configured to authenticate targeted LDP sessions using MD5, the finding will remain as a CAT II.'
  desc 'fix', 'The severity level can be downgraded to a category 3 if the router is configured to authenticate targeted LDP sessions using MD5 as shown in the example below.

RP/0/0/CPU0:R3(config)#mpls ldp
RP/0/0/CPU0:R3(config-ldp)#neighbor 10.1.1.1
RP/0/0/CPU0:R3(config-ldp)#neighbor password clear xxxxxxxx
RP/0/0/CPU0:R3(config-ldp)#neighbor 10.1.2.1
RP/0/0/CPU0:R3(config-ldp)#neighbor password clear xxxxxxxx
RP/0/0/CPU0:R3(config-ldp)#commit'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18026r507365_chk'
  tag severity: 'medium'
  tag gid: 'V-216794'
  tag rid: 'SV-216794r531087_rule'
  tag stig_id: 'CISC-RT-000660'
  tag gtitle: 'SRG-NET-000343-RTR-000001'
  tag fix_id: 'F-18024r507366_fix'
  tag 'documentable'
  tag legacy: ['SV-105933', 'V-96795']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
