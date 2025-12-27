control 'SV-221637' do
  title 'The Workspace ONE UEM server or platform must be configured to initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user (MDM system administrator) stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock, but may be at the application level where the application interface window is secured instead.

SFR ID: FMT_SMF.1.1(2) c.8"
  desc 'check', 'Review the Workspace ONE UEM server or platform configuration and verify the server is configured to lock after 15 minutes of inactivity.

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Navigate to Groups & Settings >> All Settings >> Admin >> Console Security >> Session Management.
3. Examine value present in "Idle Session Timeout" (value is number of minutes).

If the MDM console [configuration setting] is not set to 15 minutes or less, this is a finding.'
  desc 'fix', 'Configure the Workspace ONE UEM server or platform to lock the server after 15 minutes of inactivity.

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Navigate to Groups & Settings >> All Settings >> Admin >> Console Security >> Session Management.
3. Specify the value for "Idle Session Timeout" as 15 and click "Save".'
  impact 0.5
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23352r416749_chk'
  tag severity: 'medium'
  tag gid: 'V-221637'
  tag rid: 'SV-221637r588007_rule'
  tag stig_id: 'VMW1-00-000460'
  tag gtitle: 'PP-MDM-411047'
  tag fix_id: 'F-23341r416750_fix'
  tag 'documentable'
  tag legacy: ['SV-111273', 'V-102317']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
