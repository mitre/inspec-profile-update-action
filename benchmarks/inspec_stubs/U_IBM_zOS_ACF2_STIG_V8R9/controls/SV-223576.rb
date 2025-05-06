control 'SV-223576' do
  title 'IBM z/OS must employ a session manager to manage session lock after a 15-minute period of inactivity.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.'
  desc 'check', 'Ask the system administrator for the configuration parameters for the session manager in use.

If there is no session manager in use, this is a finding.

If the session manager is not configured to initiate session lock after a 15-minute period of inactivity this is a finding.'
  desc 'fix', 'Configure the session manager to initiate a session lock after a 15-minute period of inactivity.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25249r500863_chk'
  tag severity: 'medium'
  tag gid: 'V-223576'
  tag rid: 'SV-223576r533198_rule'
  tag stig_id: 'ACF2-OS-002360'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-25237r500864_fix'
  tag 'documentable'
  tag legacy: ['SV-106961', 'V-97857']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
