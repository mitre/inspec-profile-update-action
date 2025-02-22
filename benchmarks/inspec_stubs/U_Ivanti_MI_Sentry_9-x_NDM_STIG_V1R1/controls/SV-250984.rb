control 'SV-250984' do
  title 'MobileIron Sentry must initiate a session lock after a 15-minute period of inactivity.'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device. Rather than relying on the user to manually lock their management session prior to vacating the vicinity, network devices need to be able to identify when a management session has idled and take action to initiate the session lock. Once invoked, the session lock shall remain in place until the administrator reauthenticates. No other system activity aside from reauthentication shall unlock the management session.

Note that CCI-001133 requires that administrative network sessions be disconnected after 10 minutes of idle time. So this requirement may only apply to local administrative sessions.'
  desc 'check', 'Verify the System manager Timeout is set to 15 minutes.

1. Log in to the MobileIron Sentry System Manager.
2. Navigate to Settings >> Timeout.
3. Verify the System Manager timeout is set to 15.

If the System Manager timeout is not set to 15, this is a finding.'
  desc 'fix', 'Set the System Manager Timeout to 15 minutes.

1. Log in to the MobileIron Sentry System Manager.
2. Navigate to Settings >> Timeout.
3. Configure the System Manager timeout to 15.
4. Click "Apply" and "Save" in the top right corner.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54419r802172_chk'
  tag severity: 'medium'
  tag gid: 'V-250984'
  tag rid: 'SV-250984r802174_rule'
  tag stig_id: 'MOIS-ND-000050'
  tag gtitle: 'SRG-APP-000003-NDM-000202'
  tag fix_id: 'F-54373r802173_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
