control 'SV-70445' do
  title 'The ALG providing user access control intermediary services must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their session prior to vacating the vicinity, network elements need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services."
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG initiates a session lock after a 15-minute period of inactivity.

If the ALG does not initiate a session lock after a 15-minute period of inactivity, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to initiate a session lock after a 15-minute period of inactivity.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-56741r2_chk'
  tag severity: 'medium'
  tag gid: 'V-56191'
  tag rid: 'SV-70445r1_rule'
  tag stig_id: 'SRG-NET-000514-ALG-000514'
  tag gtitle: 'SRG-NET-000514-ALG-000514'
  tag fix_id: 'F-61067r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
