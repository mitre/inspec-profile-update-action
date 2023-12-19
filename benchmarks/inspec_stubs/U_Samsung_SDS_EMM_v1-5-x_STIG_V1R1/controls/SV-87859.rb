control 'SV-87859' do
  title 'The Samsung SDS EMM server or platform must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system-level and results in a system lock but may be at the application-level where the application interface window is secured instead.

SFR ID: FMT_SMF.1.1(1) Refinement"
  desc 'check', 'Review the Samsung SDS EMM server or platform configuration to determine whether the system is locked after 15 minutes. Clock the time on a server to validate that it is correctly enforcing the time period.

If the session lock does not occur within 15 minutes of inactivity, this is a finding.'
  desc 'fix', 'To configure the Samsung SDS EMM server or platform to lock the server after 15 minutes of inactivity do the following:
1) Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2) Click the “v” symbol at the top right of the web page to get a pull-down menu.
3) Choose “Configure session timeout”.
4) Set the Session Timeout(min) value to "15".
5) Click on the “Save” button.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM 1.5.x'
  tag check_id: 'C-73309r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73207'
  tag rid: 'SV-87859r1_rule'
  tag stig_id: 'SEMM-15-100010'
  tag gtitle: 'PP-MDM-991010'
  tag fix_id: 'F-79653r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
