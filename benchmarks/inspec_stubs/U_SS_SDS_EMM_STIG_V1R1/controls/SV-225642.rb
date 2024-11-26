control 'SV-225642' do
  title 'The Samsung SDS EMM or platform must be configured to initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user (MDM system administrator) stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to leaving the vicinity, applications must be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock but may be at the application level where the application interface window is secured instead.

SFR ID: FMT_SMF.1.1(2) c.8"
  desc 'check', 'Review the Samsung SDS EMM or platform configuration and verify the server is configured to lock after 15 minutes of inactivity.

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Click the arrow next to the Admin account ID in the header of main page and verify the "Set Session Timeout" is set to 15 minutes or less.

If the MDM console session time out is not set to 15 minutes or less, this is a finding.'
  desc 'fix', 'Configure the Samsung SDS EMM or platform to lock the server after 15 minutes of inactivity.

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Click the arrow next to the Admin account ID in the header of the main page and select "Set Session Timeout".
3. Enter 15 minutes in "Session Timeout (min)" and click "Save".'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27343r547711_chk'
  tag severity: 'medium'
  tag gid: 'V-225642'
  tag rid: 'SV-225642r547713_rule'
  tag stig_id: 'SSDS-00-000470'
  tag gtitle: 'PP-MDM-411047'
  tag fix_id: 'F-27331r547712_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
