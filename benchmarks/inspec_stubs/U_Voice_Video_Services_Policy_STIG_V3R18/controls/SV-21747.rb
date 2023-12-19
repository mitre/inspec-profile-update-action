control 'SV-21747' do
  title 'Enclaves with commercial VoIP connections must be approved by the DoDIN Waiver Panel and signed by DOD CIO for a permanent alternate connection to the Internet Telephony Service Provider (ITSP).'
  desc 'The DoD requires the use of DISN services as the first choice to meet core communications needs. When additional services for SIP trunks are necessary, an ITSP may provide an “alternate connection” but this requires approval by the DoDIN Waiver Panel and signature by the DoD CIO. Local ISP connections provide an Internet pathway into the DISN, placing the DoDIN directly at risk for exploitation. A local ISP connection can circumnavigate DoD protections of the DISN at its boundaries with the Internet. Using commercial VoIP service from an ITSP requires the implementation of an internet service provider (ISP) connection, potentially providing a path to the Internet. These types of connections must be approved and must meet the requirements in the Network Infrastructure STIG (NET0160) for an Internet Access Point (IAP).

ITSP connections may provide SIP trunks terminating on a media gateway, which then provides TDM trunks or POTS lines to traditional non-VoIP PBX, key system, or individual end instrument. ITSP connections terminating in a separate LAN from the enclave’s DoD LAN may support a separate VoIP system. This connection type might be used for a small site having a small VoIP system or a few discrete phones dedicated to commercial network calling. 

Additional guidance for the selection and procurement of telecommunications services is discussed in the DoDI 8100.4 "DoD Unified Capabilities (UC)" dated 9 Dec 2010 and the DoD Unified Capabilities Requirements 2013 (UCR 2013) documents.'
  desc 'check', 'Inspect the VVoIP implementation system design for connections to commercial VoIP ITSP. If the ITSP is providing converged services or other services beyond SIP trunking, NET0160 applies.

The use cases applicable to this requirement:
Use Case 1: ITSP connections providing direct connection to the enclave’s DoD LAN.
Use Case 2: ITSP connections providing a SIP trunk terminating on a media gateway that provides TDM trunks or POTS lines to traditional non-VoIP PBX, key system, or individual end instrument.
Use Case 3: ITSP connections terminating on a separate LAN from the enclave’s DoD LAN supporting a separate VoIP system.
Use Case 4: ITSP connections providing service over any approved ISP gateway.

If any enclave connects with commercial VoIP provider (ITSP) and is not approved by the DoDIN Waiver Panel, this is a finding. If the DOD CIO has not signed for a permanent “alternate connection” to the ITSP, this is a finding.

NOTE: This connection will be a permanent connection and should be designated or recognized as such in the approval documentation since most such approvals are for temporary connections.'
  desc 'fix', 'Obtain approval by the DoDIN Waiver Panel and signature by the DOD CIO for a permanent “alternate connection” to the ITSP for any connection with a commercial VoIP provider (ITSP).'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23890r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19606'
  tag rid: 'SV-21747r1_rule'
  tag stig_id: 'VVoIP 7100 (ITSP)'
  tag gtitle: 'VVoIP 7100 (ITSP)'
  tag fix_id: 'F-20305r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'EBCR-1'
end
