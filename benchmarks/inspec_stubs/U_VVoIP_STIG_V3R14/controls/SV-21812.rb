control 'SV-21812' do
  title 'The Session Border Controller (SBC) must be configured to manage IP port pinholes for the SRTP/SRTCP bearer streams based on the information in the SIP and AS-SIP messages.'
  desc 'The function of the SBC is to manage SIP and AS-SIP signaling messages. The SBC also manages the SRTP/SRTCP bearer streams. The DISN IPVS PMO has determined that the SBC will pass the negotiated and encrypted SRTP/SRTCP bearer streams without decryption and inspection. This is because doing so will not provide a significant security benefit but would cause a significant delay with a resulting decrease in the quality of the communications. Encoded audio and video is difficult to impossible to determine if an attack is being perpetrated or if sensitive information is being improperly disclosed without reconstituting the analog audio and video signals and having a person listen and watch each communication. Due to the volume of communications, to do so would be nearly impossible.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

Ensure the DISN NIPRNet IPVS SBC is configured to manage IP port pinholes for the SRTP/SRTCP bearer streams based on the information in the SIP and AS-SIP messages as follows:
- Opens specific IP port pinholes on a per session basis for the SRTP/SRTCP bearer streams as negotiated by the communicating endpoints through the LSC and MFSS.
- Closes the specifically opened IP port pinholes when the session is to be torn down.

Inspect the configurations of the EBC to determine compliance with the requirement.

If the SBC is not configured to open the specifically negotiated IP ports for the SRTP/SRTCP bearer streams on an individual session basis, this is a finding. If the SBC is not configured to close specifically negotiated IP ports for the SRTP/SRTCP bearer streams on an individual session basis, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Ensure the DISN NIPRNet IPVS SBC is configured to manage IP port pinholes for the SRTP/SRTCP bearer streams based on the information in the SIP and AS-SIP messages as follows:
- Opens specific IP port pinholes on a per session basis for the SRTP/SRTCP bearer streams as negotiated by the communicating endpoints through the LSC and MFSS.
- Closes the specifically opened IP port pinholes when the session is to be torn down.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24051r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19671'
  tag rid: 'SV-21812r3_rule'
  tag stig_id: 'VVoIP 6330'
  tag gtitle: 'VVoIP 6330'
  tag fix_id: 'F-20377r2_fix'
  tag 'documentable'
end
