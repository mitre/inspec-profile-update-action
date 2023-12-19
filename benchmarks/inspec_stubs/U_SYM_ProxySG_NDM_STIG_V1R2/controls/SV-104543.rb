control 'SV-104543' do
  title 'Symantec ProxySG must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed Symantec ProxySG.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

By default, when a user logs off of the session all session attributes are terminated. For abruptly terminated sessions, the Keep-alive default is 2 minutes and then the session is terminated and cleans up. This is inherent to the system and cannot be misconfigured.'
  desc 'check', 'If there is a documented and validated mission requirement which allows the inactivity period to exceed "10" minutes, this is not a finding.

Verify the device management session inactivity timeouts are set to "10" minutes.

1. Log on to the Web Management Console.
2. Click Configuration >> Authentication >> Console Access >> Console Account.
3. Confirm that the "Enforce Web auto-logout" and "Enforce CLI auto-logout" options are set to "10" minutes.

If Symantec ProxySG is not configured to terminate the management session after "10" minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure the device management session inactivity timeouts to "10" minutes.

1. Log on to the Web Management Console.
2. Click Configuration >> Authentication >> Console Access >> Console Account.
3. Set "Enforce Web auto-logout" and "Enforce CLI auto-logout" to "10" minutes.'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93903r1_chk'
  tag severity: 'high'
  tag gid: 'V-94713'
  tag rid: 'SV-104543r1_rule'
  tag stig_id: 'SYMP-NM-000310'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-100831r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
