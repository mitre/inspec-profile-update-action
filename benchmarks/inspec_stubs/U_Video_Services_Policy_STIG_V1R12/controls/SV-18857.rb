control 'SV-18857' do
  title 'VTC data in transit must be encrypted.'
  desc 'Early VTC CODECs did not support confidentiality of the media or signaling streams directly. As security and conference confidentiality have become an IA concern, VTU vendors have standardized on DES and AES encryption standards for VTC media streams. H.235 has been developed to help to secure the signaling protocols used in the H.323 suite of protocols. Most VTC media traffic is considered to be sensitive information requiring protection. Minimally all endpoints and MCUs must employ FIPS-validated or NSA-approved cryptography for data in transit, including both media and signaling.

Much of the legacy VTC gear used today either supports DES or has no encryption. Newer CODECs support FIPS 140-2 encryption for media and signaling and typically have three encryption options on, off or automatic/negotiate. The preferred setting is ON and used when the other VTUs that a VTU needs to communicate with support encryption. Auto/negotiate is the preferred setting when this is not known.'
  desc 'check', 'If a VTU under review is connected to classified IP networks and the conference information owners provide is written confirmation that encryption is not required within the classified enclave, this requirement is not applicable.

If the VTC systems, endpoints, and MCUs under review are on a physically separate network from the enclave’s LAN and use dedicated point-to-point circuits outside the enclave to interconnect to MCUs and other endpoints, this requirement is not applicable.

If the VTC systems, endpoints, and MCUs under review are on a logically separate network on the enclave’s LAN using a dedicated and closed VTC VLAN, and protected on the WAN using an encrypted VPN between endpoints and the MCU, this requirement is not applicable.

Review the VTC system architecture and ensure the VTC data in transit is encrypted. If the VTC data in transit is not encrypted, this is a finding.

Ensure the strongest encryption algorithm is used for VTC media streams as supported by all communicating VTUs and associated MCUs.'
  desc 'fix', 'Configure the VTC system architecture to require all data in transit be encrypted, with a preference for FIPS-validated or NSA-approved cryptography over legacy encryption.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18953r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17683'
  tag rid: 'SV-18857r2_rule'
  tag stig_id: 'RTS-VTC 1220.00'
  tag gtitle: 'RTS-VTC 1220'
  tag fix_id: 'F-17580r2_fix'
  tag 'documentable'
  tag severity_override_guidance: '[ISDN] Reduce to CAT III for legacy ISDN/dialup MCUs or VTUs when these will not interoperate using native/internal encryption options. This is typical between equipment of different vendors legacy equipment. Mitigation using external encryption devices is acceptable.

[Unclassified IP] Reduce to CAT III for VTC systems when every information owner designates their information is publicly releasable or their non-public information does not require encryption. Each conference information owner must provide written confirmation that encryption is not necessary.

During APL testing:
- This is a CAT I finding in the event the CODEC does not support multi-vendor interoperable encryption or it supports DES encryption only. (This applies only to new, non-legacy products submitted for testing.)'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECCT-1, ECNK-1, ECSC-1'
end
