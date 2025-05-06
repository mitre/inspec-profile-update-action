control 'SV-21803' do
  title 'The Customer Edge Router (CE-R) must expedite forwarding of VVoIP packets based on Differential Service Code Point (DSCP) packet marking.'
  desc 'The typical perimeter or premise router may not be capable of supporting the needs of VVoIP and UC when entering the DISN WAN. Modern routers are capable of dealing with service classes and expedited forwarding. This why the DISN IPVS PMO specifies the specific additional capabilities required of the perimeter or premise router to support the needs of the Assures Service network. The router designated by the DISN IPVS PMO needed to support the service is the CE-R. The CE-R provides the following functionality:
- Provides minimally four forwarding cues (eight preferred)
- Places traffic within expedited forwarding cues based on the DSCP markings carried by the traffic.
- Routes inbound AS-SIP-TLS packets and SRTP/SRTCP packets to the Session Border Controller (SBC).
- Routes SIP and SRTP traffic encapsulated on port 443 to the SBC.
- Routes all other inbound traffic to the data firewall.
- Provides all of the filtering required of a perimeter or premise router as required by the Router STIG.

Proper DSCP marking of VVoIP packets is required to provide appropriate QoS for Command and Control (C2) priority calls in support of Assured Service.'
  desc 'check', 'Review site documentation to confirm the CE-R expedites forwarding of VVoIP packets based on DSCP packet marking. When the VVoIP system connects to the DISN WAN for VVoIP transport between enclaves and the system provides Assured Services to any C2 user (Special-C2, C2, or C2-R), the required CE-R must expedite forwarding of VVoIP packets based on DSCP packet marking in accordance with the DISN IPVS DSCP marking plan. Proper DSCP marking provides appropriate QoS for C2 priority calls in support of Assured Service. 

If the CE-R does not expedite forwarding of VVoIP packets based on DSCP packet marking, this is a finding.

NOTE: The CE-R must allow traditional SIP and SRTP traffic, and traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Implement the CE-R to expedite forwarding of VVoIP packets based on DSCP packet marking.

NOTE: The CE-R must allow traditional SIP and SRTP traffic, and traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24030r3_chk'
  tag severity: 'medium'
  tag gid: 'V-19662'
  tag rid: 'SV-21803r4_rule'
  tag stig_id: 'VVoIP 6205'
  tag gtitle: 'VVoIP 6205'
  tag fix_id: 'F-20367r3_fix'
  tag 'documentable'
end
