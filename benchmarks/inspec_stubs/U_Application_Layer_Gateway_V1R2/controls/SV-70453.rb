control 'SV-70453' do
  title 'The ALG providing user access control intermediary services must provide a logoff capability for user-initiated communications sessions.'
  desc 'If a user cannot explicitly end a session, the session may remain open and be exploited by an attacker.

However, for some types of interactive sessions including, for example, remote logon, information systems typically send logoff messages as final messages prior to terminating sessions.

This policy only applies to gateways (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG provides a logoff capability for user-initiated communications sessions.

If the ALG does not provide a logoff capability for user-initiated communications sessions, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to provide a logoff capability for user-initiated communications sessions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-56749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56199'
  tag rid: 'SV-70453r1_rule'
  tag stig_id: 'SRG-NET-000518-ALG-000007'
  tag gtitle: 'SRG-NET-000518-ALG-000007'
  tag fix_id: 'F-61075r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
