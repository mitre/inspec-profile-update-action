control 'SV-223573' do
  title 'IBM z/OS must employ a session manager to manage retaining a users session lock until that user reestablishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.'
  desc 'check', "Ask the system administrator for the configuration parameters for the session manager in use.

If there is no session manager in use, this is a finding.

If the session manager is not configured to retain a user's session lock until that user reestablishes access using established identification and authentication procedures, this is a finding."
  desc 'fix', "Configure the session manager to retain a user's session lock until that user reestablishes access using established identification and authentication procedures."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25246r500854_chk'
  tag severity: 'medium'
  tag gid: 'V-223573'
  tag rid: 'SV-223573r533198_rule'
  tag stig_id: 'ACF2-OS-002240'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-25234r500855_fix'
  tag 'documentable'
  tag legacy: ['V-97851', 'SV-106955']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
