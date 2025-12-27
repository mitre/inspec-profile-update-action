control 'SV-253511' do
  title 'DocAve must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications must be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system-level and results in a system lock but may be at the application-level where the application interface window is secured instead."
  desc 'check', 'Check the DocAve Manager Session Timeout setting.
- Log on to DocAve with admin account.
- On the Control Panel page, in the System Options section, click "Security Settings". 
- Select the "System Security Policy" tab.
- Verify Logon Will Expire is set to "15" minutes or less.

If the Logon Will Expire is not set to "15" minutes or less, this is a finding.'
  desc 'fix', 'Configure the DocAve Manager Session Timeout setting.
- Log on to DocAve with admin account.
- On the Control Panel page, in the System Options section, click "Security Settings". 
- Select the "System Security Policy" tab.
- Set Logon Will Expire to "15" minutes or less.
- Save the settings.'
  impact 0.5
  ref 'DPMS Target AvePoint DocAve 6'
  tag check_id: 'C-56963r836506_chk'
  tag severity: 'medium'
  tag gid: 'V-253511'
  tag rid: 'SV-253511r836508_rule'
  tag stig_id: 'DCAV-00-000003'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-56914r836507_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
