control 'SV-70449' do
  title 'The ALG providing user access control intermediary services must retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Regardless of where the session lock is determined and implemented, once invoked the session lock shall remain in place until the user re-authenticates. No other activity aside from re-authentication shall unlock the system.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG retains the session lock until the user reestablishes access using established identification and authentication procedures.

If the ALG does not retain the session lock until the user reestablishes access using established identification and authentication procedures, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-56745r2_chk'
  tag severity: 'medium'
  tag gid: 'V-56195'
  tag rid: 'SV-70449r1_rule'
  tag stig_id: 'SRG-NET-000516-ALG-000516'
  tag gtitle: 'SRG-NET-000516-ALG-000516'
  tag fix_id: 'F-61071r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
