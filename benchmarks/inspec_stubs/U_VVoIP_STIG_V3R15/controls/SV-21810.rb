control 'SV-21810' do
  title 'The Session Border Controller (SBC) must be configured to validate the structure and validity of SIP and AS-SIP messages, such that malformed messages or messages containing errors are dropped before action is taken on the contents.'
  desc 'Malformed SIP and AS_SIP messages as well as messages containing errors could be an indication that an adversary is attempting some form of attack or denial-of-service. Such an attack is called fuzzing. Fuzzing is the deliberate sending of signaling messages that contain errors in an attempt to cause the target device to react in an inappropriate manner, such as the device could fail causing a denial-of-service or could permit traffic to pass that it would not normally permit. In some cases a target can be flooded with fuzzed messages. As such the SBC must not act on any portion of a signaling message that contains errors. It is possible that a malformed or erroneous message could be sent by the signaling partner and be properly hashed for integrity.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

Verify the DISN NIPRNet IPVS SBC is configured to validate the structure and validity of SIP and AS-SIP messages such that malformed messages or messages containing errors are dropped before action is taken on the contents.

If the SBC does not validate the correct format of the received AS-SIP message, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Ensure the DISN NIPRNet IPVS SBC is configured to validate the structure and validity of SIP and AS-SIP messages such that malformed messages or messages containing errors are dropped before action is taken on its contents.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.3
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24047r2_chk'
  tag severity: 'low'
  tag gid: 'V-19669'
  tag rid: 'SV-21810r3_rule'
  tag stig_id: 'VVoIP 6320'
  tag gtitle: 'VVoIP 6320'
  tag fix_id: 'F-20375r2_fix'
  tag 'documentable'
end
