control 'SV-223583' do
  title 'IBM z/OS must employ a session manager configured for users to directly initiate a session lock for all connection types.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session should the need arise for them to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Ask the system administrator for the configuration parameters for the session manager in use.

If there is no session manager in use, this is a finding.

If the session manager in use does not allow users to directly initiate a session lock for all connection types, this is a finding.'
  desc 'fix', 'Configure the session manage to allow users to directly initiate a session lock for all connection types.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25256r500884_chk'
  tag severity: 'medium'
  tag gid: 'V-223583'
  tag rid: 'SV-223583r533198_rule'
  tag stig_id: 'ACF2-OS-002440'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-25244r500885_fix'
  tag 'documentable'
  tag legacy: ['V-97871', 'SV-106975']
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
