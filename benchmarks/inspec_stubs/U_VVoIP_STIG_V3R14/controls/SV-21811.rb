control 'SV-21811' do
  title 'The Session Border Controller (SBC) must drop all SIP and AS-SIP packets except those secured with TLS.'
  desc 'DISN NIPRNet IPVS PMO and the UCR require all session signaling across the DISN WAN and between the LSC and EBC to be secured with TLS. The standard IANA assigned IP port for SIP protected by TLS (SIP-TLS) is 5061. DoD PPSM requires that protocols traversing the DISN and DoD enclave boundaries use the standard IP ports for the specific protocol. Since AS-SIP is a standardized extension of the SIP protocol and since AS-SIP must be protected by TLS, AS-SIP-TLS must use IP port 5061. The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated using TLS on port 443 from Cloud Service Providers.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement:

Ensure the DISN NIPRNet IPVS SBC is configured to drop the following signaling packets:
- SIP packets arriving on IP port 5060 or 5061
- SIP packets arriving on IP port 443 not secured with TLS
- AS-SIP packets arriving on IP port 5060 
- AS-SIP packets arriving on IP port 5061 not secured with TLS

If all SIP and AS-SIP packets are not dropped except AS-SIP packets secured with TLS arriving on IP Port 5061 and SIP packets secured with TLS arriving on IP Port 443 secured with TLS, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Ensure the DISN NIPRNet IPVS SBC is configured to drop the following signaling packets:
- SIP packets arriving on IP port 5060 or 5061
- SIP packets arriving on IP port 443 not secured with TLS
- AS-SIP packets arriving on IP port 5060 
- AS-SIP packets arriving on IP port 5061 not secured with TLS

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24049r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19670'
  tag rid: 'SV-21811r3_rule'
  tag stig_id: 'VVoIP 6325'
  tag gtitle: 'VVoIP 6325'
  tag fix_id: 'F-20376r2_fix'
  tag 'documentable'
end
