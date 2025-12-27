control 'SV-258608' do
  title 'The ICS must be configured to terminate after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

Upon the termination of a session, the Ivanti ICS inherently ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'In the ICS Web UI, navigate to Administrators >> Admins Role >> Delegated Admin Roles.
1. Click the configured admin role being used for CAC/PKI token admin logins (by default it is .Administrators).
2. Click the Session Options tab.
3. In the "Session Lifetime" section, verify the Idle Timeout is set to "10".

If the ICS does not terminate after 10 minutes of inactivity except to fulfill documented and validated mission requirements, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Administrators >> Admins Role >> Delegated Admin Roles.

1. Click the configured admin role being used for CAC/PKI token admin logins, by default it is .Administrators.
2. Click the Session Options tab.
3. In the "Session Lifetime" section, set the Idle Timeout to "10".
4. Click "Save Changes".'
  impact 0.7
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62348r930510_chk'
  tag severity: 'high'
  tag gid: 'V-258608'
  tag rid: 'SV-258608r930512_rule'
  tag stig_id: 'IVCS-NM-000300'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-62257r930511_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
