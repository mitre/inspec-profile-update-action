control 'SV-21808' do
  title 'The Session Border Controller (SBC) must be configured to only process packets authenticated from an authorized source within the DISN IPVS network.'
  desc 'The function of the SBC is to manage SIP and AS-SIP signaling messages. The SBC also authenticates SIP and AS-SIP signaling messages, ensuring they are from an authorized source. DoD policy dictates that authentication be performed using DoD PKI certificates. This also applies to network hosts and elements. SIP and AS-SIP are not a secure protocols. The information passed during a call session is in human readable plain text. To secure SIP and AS-SIP, TLS is used. TLS is PKI certificate based and is used for AS-SIP message encryption, authentication, and integrity validation. 

NOTE: Authentication is provided by validating the sending appliance’s public PKI certificate used to establish the TLS session. AS-SIP messages are not sent until the authenticated TLS session is established.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

Ensure the DISN NIPRNet IPVS SBC is configured to only process packets authenticated from an authorized source as follows:
- Authenticate outbound SIP and AS-SIP messages as being from the primary or backup LSC (or the site’s MFSS and its backup LSC) within the enclave.
- Authenticate inbound SIP and AS-SIP messages as being from the SBC at the enclave’s assigned primary and secondary (backup) MFSS sites.

Inspect the configurations of the EBC to determine compliance with the requirement.

If the SBC does not use DoD PKI to authenticate the source of SIP and AS-SIP packets, this is a finding. the SBC is not configured to validate sending appliance’s public PKI certificate against the DoD PKI registry and CRLs, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Ensure the DISN NIPRNet IPVS SBC is configured to only process packets authenticated from an authorized source as follows:
- Authenticate outbound SIP and AS-SIP messages as being from the primary or backup LSC (or the site’s MFSS and is backup LSC) within the enclave.
- Authenticate inbound SIP and AS-SIP messages as being from the SBC at the enclave’s assigned primary and secondary (backup) MFSS sites.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24043r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19667'
  tag rid: 'SV-21808r3_rule'
  tag stig_id: 'VVoIP 6310'
  tag gtitle: 'VVoIP 6310'
  tag fix_id: 'F-20373r2_fix'
  tag 'documentable'
end
