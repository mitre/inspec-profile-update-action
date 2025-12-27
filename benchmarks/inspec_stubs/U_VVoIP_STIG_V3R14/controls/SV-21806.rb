control 'SV-21806' do
  title 'The Session Border Controller (SBC) must filter inbound SIP and AS-SIP traffic based on the IP addresses of the internal Enterprise Session Controller (ESC), Local Session Controller (LSC), or Multi-Function Soft Switch (MFSS).'
  desc 'The SBC is in the VVoIP signaling between the LSC and MFSS. To limit exposure to compromise and DOS, the SBC must only exchange signaling messages using the designated protocol (AS-SIP-TLS) with the LSC(s) within the enclave and the SBC fronting the MFSS (and its backup) to which the LSC is assigned. 

Similarly, an SBC fronting an MFSS must only exchange signaling messages with the MFSS and LSC(s) within the enclave and the SBCs fronting other MFSSs and the LSCs assigned to it. 

While the SBC is also required to authenticate the source and integrity of the signaling packets it receives, filtering on source IP address adds a layer of protection for the MFSS. This is also a backup measure in the event this filtering is not done on the CE-R.

Internal to the enclave, filtering signaling traffic based on the IP address(es) of the LSC(s) within the enclave limits the ability of rogue Voice Video Endpoints attempting to establish calls or cause a DOS.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

Ensure the DISN NIPRNet IPVS SBC is configured to only communicate as follows:
- Within the enclave, ensure the SBC only establishes SIP and AS-SIP sessions with the primary or backup LSC or the MFSS and its backup LSC within the enclave.
- If the SBC is at a site without a MFSS: External to the enclave (across the WAN), ensure the SBC only establishes SIP and AS-SIP sessions with the SBC at the enclave’s assigned primary and secondary (backup) MFSS sites.
- If the SBC is at a MFSS site: External to the enclave (across the WAN), ensure the SBC only establishes SIP and AS-SIP sessions with SBCs located at other MFSS sites and the LSC sites assigned to it.

Determine the following:
- If the enclave contains LSCs, determine the IP address of SBCs fronting the primary and backup MFSSs to which the enclave is assigned or with which the LSC is to exchange signaling messages.
- If the enclave contains a MFSS, determine the IP addresses of the SBCs fronting the LSCs with which it is to signal. Additionally determine the IP addresses of the SBCs fronting the other MFSSs. 

If the SBC does not filter inbound SIP and AS-SIP traffic based on the IP addresses of the SBCs fronting authorized ESCs, LSCs, and MFSSs, this is a finding. Alternatively, if the SBC does not filter SIP and AS-SIP traffic based on the IP addresses of the ESCs and LSCs within the enclave, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Ensure the DISN NIPRNet IPVS SBC is configured to only communicate as follows:
- Within the enclave, ensure the SBC only establishes SIP and AS-SIP sessions with the primary or backup LSC or the MFSS and its backup LSC within the enclave.
- If the SBC is at a site without a MFSS: External to the enclave (across the WAN), ensure the SBC only establishes SIP and AS-SIP sessions with the SBC at the enclave’s assigned primary and secondary (backup) MFSS sites.
- If the SBC is at a MFSS site: External to the enclave (across the WAN), ensure the SBC only establishes SIP and AS-SIP sessions with SBCs located at other MFSS sites and the LSC sites assigned to it.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24039r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19665'
  tag rid: 'SV-21806r3_rule'
  tag stig_id: 'VVoIP 6300'
  tag gtitle: 'VVoIP 6300'
  tag fix_id: 'F-20371r2_fix'
  tag 'documentable'
end
