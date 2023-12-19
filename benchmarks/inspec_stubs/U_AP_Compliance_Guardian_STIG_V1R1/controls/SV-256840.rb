control 'SV-256840' do
  title 'Compliance Guardian must initiate a session timeout after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications must identify when a user's session has idled and initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock but may be at the application level where the application interface window is secured instead."
  desc 'check', 'Check the Compliance Guardian Manager Session Timeout setting.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page, in the System Configuration section, click "General Settings". 
- Select "Security - System Security Policy".
- Verify the "Please specify a session time-out value". The user will be logged off automatically if there is no activity for the specified period. Logon will expire in option.

If the session timeout value is not set to 15 minutes or less, this is a finding.'
  desc 'fix', 'Configure the Compliance Guardian Manager Session Timeout setting.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page, in the System Configuration section, click "General Settings". 
- Select "Security - System Security Policy".
- Set 15 minutes or less in the "Please specify a session time-out value". The user will be logged off automatically if there is no activity for the specified period. Logon will expire in option.
- Save the settings.'
  impact 0.5
  ref 'DPMS Target AvePoint Compliance Guardian'
  tag check_id: 'C-60515r890128_chk'
  tag severity: 'medium'
  tag gid: 'V-256840'
  tag rid: 'SV-256840r890130_rule'
  tag stig_id: 'APCG-00-000005'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-60458r890129_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
