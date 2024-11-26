control 'SV-21804' do
  title 'The Customer Edge Router (CE-R) must route all inbound traffic to the data firewall function except SIP, AS-SIP, and SRTP/SRTCP, which must route to the Session Border Controller (SBC).'
  desc 'The CE-R is the first line of defense at the gateway to the enclave or LAN. The data firewall and SBC functions are the second line of defense. Since the SBC function only processes VVoIP traffic in the form of SIP, AS-SIP, and SRTP/SRTCP packets, the CE-R should only forward these packets to the SBC, including SIP and SRTP traffic encapsulated on port 443. All other traffic must be forwarded to the data firewall.'
  desc 'check', 'Review site documentation to confirm the CE-R routes all inbound traffic to the data firewall function except SIP, AS-SIP, and SRTP/SRTCP, which must route to the SBC. This supports the VVoIP system connecting to the DISN WAN for VVoIP transport between enclaves and the system providing Assured Services to any Command and Control (C2) user (Special-C2, C2, or C2-R). 

If the CE-R does not route all inbound traffic to the data firewall function except SIP, AS-SIP, and SRTP/SRTCP, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Implement the CE-R to route all inbound traffic to the data firewall function except SIP, AS-SIP, and SRTP/SRTCP, which must route to the SBC.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24032r3_chk'
  tag severity: 'medium'
  tag gid: 'V-19663'
  tag rid: 'SV-21804r4_rule'
  tag stig_id: 'VVoIP 6210'
  tag gtitle: 'VVoIP 6210'
  tag fix_id: 'F-20368r3_fix'
  tag 'documentable'
end
