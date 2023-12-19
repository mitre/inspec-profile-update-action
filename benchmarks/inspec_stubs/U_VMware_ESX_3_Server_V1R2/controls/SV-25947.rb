control 'SV-25947' do
  title 'The system must display the number of unsuccessful login attempts since the last successful login for a user account upon logging in.'
  desc 'Providing users with feedback on recent login failures facilitates user recognition and reporting of attempted unauthorized account use.'
  desc 'check', 'Determine if the system displays the number of failed login attempts upon logging in.  Attempt to log into the system once using an invalid password or other authenticator, then log into the system using the same account with a valid authenticator. If the system does not display a message indicating there was a failed login attempt, this is a finding.'
  desc 'fix', 'Configure the system to display the number of failed logins upon logging in. Consult OS documentation for the necessary procedure.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30375r1_chk'
  tag severity: 'low'
  tag gid: 'V-22300'
  tag rid: 'SV-25947r1_rule'
  tag stig_id: 'GEN000454'
  tag gtitle: 'GEN000454'
  tag fix_id: 'F-27155r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000053']
  tag nist: ['AC-9 (1)']
end
