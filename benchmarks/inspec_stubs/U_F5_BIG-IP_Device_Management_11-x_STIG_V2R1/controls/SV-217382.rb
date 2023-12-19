control 'SV-217382' do
  title 'The BIG-IP appliance must be configured to initiate a session lock after a 10-minute period of inactivity.'
  desc 'A session lock is a temporary network device- or administrator-initiated action taken when the administrator stops work but does not log out of the network device. Rather than relying on the user to manually lock their management session prior to vacating the vicinity, network devices need to be able to identify when a management session has idled and take action to initiate the session lock. Once invoked, the session lock shall remain in place until the administrator re-authenticates. No other system activity aside from re-authentication shall unlock the management session.

Note that CCI-001133 requires that administrative network sessions be disconnected after 10 minutes of idle time. So this requirement may only apply to local administrative sessions.'
  desc 'check', 'Verify the BIG-IP appliance is configured to initiate a session lock after a 10-minute period of inactivity.

Navigate to the BIG-IP System manager >> System >> Preferences.

Under "Security Settings", ensure that "Idle Time Before Automatic Logout" is less than or equal to 600 seconds. 

If a session lock is not initiated after a 10-minute period of inactivity, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to initiate a session lock after a 10-minute period of inactivity.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18607r290700_chk'
  tag severity: 'medium'
  tag gid: 'V-217382'
  tag rid: 'SV-217382r557520_rule'
  tag stig_id: 'F5BI-DM-000007'
  tag gtitle: 'SRG-APP-000003-NDM-000202'
  tag fix_id: 'F-18605r290701_fix'
  tag 'documentable'
  tag legacy: ['SV-74523', 'V-60093']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
