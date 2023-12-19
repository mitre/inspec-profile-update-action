control 'SV-17099' do
  title 'Unified Capabilities (UC) soft clients must be supported by the manufacturer or vendor.'
  desc 'One of the measures to protect UC soft clients and collaboration applications is to ensure the application originates from a reputable source. The source of these applications can vary depending upon the type of application. To protect DoD interests, the source of the application depends on the criticality of the communications method. One source for compromise of a communications application is the use of freeware or shareware applications. Communications applications that provide voice communications must be designed to properly interoperate with the VoIP system. These applications should be a standard product of the voice system vendor or a partner whose product is approved by this vendor. 

Some UC soft clients provide VTC and collaboration features and should be sourced from the voice system vendor. Applications providing VTC features that interoperate directly with a hardware based VTC system should be sourced from the VTC system’s vendor or a partner whose product is approved by this vendor. Other UC soft clients that provide collaboration services while also providing voice and video communications features must also be sourced from a major vendor in the business of providing collaboration systems or services. UC soft clients that provide multiple services such as IM, presence, voice, VTC, web conferencing, and so forth, may be integrated with the operating system, such as Microsoft’s Office Communications applications. Application sourcing can also be dependent on whether the application is to interoperate with hardware based communications system located and operated within an enclave or whether it is a system operated by an interagency or inter-base program. The vendor must be able to provide patches, upgrades or both to mitigate newly discovered vulnerabilities found in their product in a timely manner.'
  desc 'check', 'Review the site documentation to confirm the UC soft clients are supported by the manufacturer or vendor. Sources for UC soft clients include:
 - UC soft clients sourced from the enclave’s VoIP system vendor or their approved partner.
 - VTC soft clients sourced from the enclave’s or program’s VTC system vendor or their approved partner.
 - UC soft clients sourced from the enclave’s or program’s Collaboration system vendor or their approved partner.
 - The workstation operating system vendor when the application is approved to interoperate with the primary systems above. 
 - An information system program providing the application from an appropriate source with the required testing, certification, and accreditation.

If the UC soft clients are not supported by the manufacturer or vendor, this is a finding. If the source or distribution of the UC soft client is freeware or shareware, such as applications from Yahoo, MSN, Google, or Skype, this is a finding. 

NOTE: this is not a finding when the UC soft clients are shareware, freeware, or sourced from a third party other than a system vendor and the UC soft client is necessary to accomplish the mission; there are no alternative IT solutions available; and the product has been assessed for information assurance impacts, and approved for use by the AO in writing.'
  desc 'fix', 'Ensure the UC soft clients are supported by the manufacturer or vendor.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17155r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16111'
  tag rid: 'SV-17099r2_rule'
  tag stig_id: 'VVoIP 1705'
  tag gtitle: 'VVoIP 1705'
  tag fix_id: 'F-16217r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
