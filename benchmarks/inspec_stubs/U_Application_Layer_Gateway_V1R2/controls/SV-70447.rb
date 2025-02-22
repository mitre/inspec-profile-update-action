control 'SV-70447' do
  title 'The ALG providing user access control intermediary services must provide the capability for users to directly initiate a session lock.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, network elements need to provide users with the ability to manually invoke a session lock so users may secure their session should the need arise for them to temporarily vacate the immediate physical vicinity.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG provides the capability for users to directly initiate a session lock.

If the ALG does not provide the capability for users to directly initiate a session lock, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to provide the capability for users to directly initiate a session lock.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-56743r2_chk'
  tag severity: 'medium'
  tag gid: 'V-56193'
  tag rid: 'SV-70447r1_rule'
  tag stig_id: 'SRG-NET-000515-ALG-000515'
  tag gtitle: 'SRG-NET-000515-ALG-000515'
  tag fix_id: 'F-61069r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
