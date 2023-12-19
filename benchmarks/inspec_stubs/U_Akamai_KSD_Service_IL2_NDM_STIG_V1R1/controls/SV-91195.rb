control 'SV-91195' do
  title 'The Akamai Luna Portal must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 15 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Verify that all portal users have the session timeout duration set to 15 minutes:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Manage Users & Groups.
3. Select each user and inspect the "Timeout" setting to verify it reads "After 15 Minutes".

If the session timeout is not set to 15 minutes, this is a finding.'
  desc 'fix', 'Set the session timeout duration to 15 minutes:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Manage Users & Groups.
3. Select each user and adjust the "Timeout" setting to "After 15 Minutes".'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76159r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76499'
  tag rid: 'SV-91195r1_rule'
  tag stig_id: 'AKSD-DM-000038'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-83177r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
