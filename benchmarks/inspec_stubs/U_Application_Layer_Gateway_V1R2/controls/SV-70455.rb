control 'SV-70455' do
  title 'The ALG providing user access control intermediary services must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.'
  desc 'If a user cannot explicitly end a session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Logoff messages for access, for example, can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions including, for example, remote logon, information systems typically send logoff messages as final messages prior to terminating sessions.

This policy only applies to ALGs (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG displays an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.

If the ALG does not display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-56751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56201'
  tag rid: 'SV-70455r1_rule'
  tag stig_id: 'SRG-NET-000519-ALG-000008'
  tag gtitle: 'SRG-NET-000519-ALG-000008'
  tag fix_id: 'F-61077r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
