control 'SV-108125' do
  title 'The BlackBerry UEM 12.11 server or platform must be configured to initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user (UEM system administrator) stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock but may be at the application level where the application interface window is secured instead.

SFR ID: FMT_SMF.1.1(2) c.8"
  desc 'check', 'Review the BlackBerry UEM server configuration to determine whether the system is locked after 15 minutes. 

Have the system administrator log into the console. Verify the session locks after 15 minutes of inactivity.

If the "Session timeout" is not set correctly, this is a finding.'
  desc 'fix', 'On the BlackBerry UEM, do the following to set the session timeout:
1. Log in to the BlackBerry UEM console.
2. Go to the menu bar on the left.
3. Go to Settings >> General Settings >> Console.
4. Under "Session settings", enter "15".
5. Select "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry Unified Endpoint Manager (UEM) 12.11'
  tag check_id: 'C-97861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99021'
  tag rid: 'SV-108125r1_rule'
  tag stig_id: 'BUEM-12-110030'
  tag gtitle: 'PP-MDM-411047'
  tag fix_id: 'F-104697r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
