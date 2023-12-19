control 'SV-101911' do
  title 'The MobileIron Core v10 server or platform must be configured to initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user (MDM system administrator) stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock but may be at the application level where the application interface window is secured instead.

SFR ID: FMT_SMF.1.1(2) h"
  desc 'check', 'Review the MDM server or platform configuration.

Verify the server is configured to lock after "15-minutes or less" of inactivity. You will see the current value for the session timeout, in minutes.

If, in the Admin Portal, Settings >> General >> Timeout is not set to "15-minutes or less", this is a finding.'
  desc 'fix', 'Configure the MDM server or platform to lock the server after 15-minutes of inactivity.

In the Admin Portal, go to Settings >> General >> Timeout.

From the dropdown menu, choose a timeout value of "5-", "10-", or "15-minutes".'
  impact 0.5
  ref 'DPMS Target MobileIron Core 10.x MDM'
  tag check_id: 'C-90967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-91809'
  tag rid: 'SV-101911r1_rule'
  tag stig_id: 'MICR-10-000450'
  tag gtitle: 'PP-MDM-311047'
  tag fix_id: 'F-98011r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
