control 'SV-21816' do
  title 'The Session Border Controller (SBC) must be configured to notify system administrators and ISSO when attempts to cause a denial-of-service (DoS) or other suspicious events are detected.'
  desc 'Action cannot be taken to thwart an attempted denial-of-service or compromise if the system administrators responsible for the operation of the SBC and/or the network defense operators are not alerted to the occurrence in real time.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

Ensure the DISN NIPRNet IPVS SBC is configured to notify system administrators and ISSO when the following conditions occur:
- Any number of malformed SIP, AS-SIP, or SRTP/SRTCP messages are received that could indicate an attempt to compromise the SBC.
- Excessive numbers of SIP or AS-SIP messages are received from any given IP address that could indicate an attempt to cause a DoS.
- Excessive numbers of messages are dropped due to authentication or integrity check failures; potentially indicating an attempt to cause a DoS or an attempt to effect a man in the middle attack. 

If the SBC does not notify system administrators and ISSO when attempts to cause a DoS or other suspicious events are detected, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Ensure the DISN NIPRNet IPVS SBC is configured to notify system administrators and ISSO when the following conditions occur:
- Any number of malformed SIP, AS-SIP, or SRTP/SRTCP messages are received that could indicate an attempt to compromise the SBC.
- Excessive numbers of SIP or AS-SIP messages are received from any given IP address that could indicate an attempt to cause a DoS.
- Excessive numbers of messages are dropped due to authentication or integrity check failures; potentially indicating an attempt to cause a DoS or an attempt to effect a man in the middle attack.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24059r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19675'
  tag rid: 'SV-21816r3_rule'
  tag stig_id: 'VVoIP 6350'
  tag gtitle: 'VVoIP 6350'
  tag fix_id: 'F-20381r2_fix'
  tag 'documentable'
end
