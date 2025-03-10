control 'SV-91157' do
  title 'The Akamai Luna Portal must initiate a session logoff after a 15-minute period of inactivity.'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device. Rather than relying on the user to manually lock their management session prior to vacating the vicinity, network devices need to be able to identify when a management session has idled and take action to initiate the session lock. Once invoked, the session lock must remain in place until the administrator reauthenticates. No other system activity aside from reauthentication must unlock the management session.

When the network device is remotely administered, a session logoff may be the only practical option in lieu of a session lock. For a web portal, a session logoff must be invoked when idle time is exceeded for an administrator.

Note that CCI-001133 requires that administrative network sessions be disconnected after 10 minutes of idle time.'
  desc 'check', 'Verify that all portal users have the session timeout duration set to 15 minutes:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Manage Users & Groups.
3. Select each administrator and inspect the "Timeout" setting to verify it reads "After 15 Minutes".
4. Click "Save" button.

If any user has a "Timeout" value other than "After 15 Minutes", this is a finding.'
  desc 'fix', 'Configure the session timeout duration to 15 minutes:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Manage Users & Groups.
3. Select each user and set the "Timeout" value to "After 15 Minutes".'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76121r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76461'
  tag rid: 'SV-91157r1_rule'
  tag stig_id: 'AKSD-DM-000007'
  tag gtitle: 'SRG-APP-000003-NDM-000202'
  tag fix_id: 'F-83139r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
