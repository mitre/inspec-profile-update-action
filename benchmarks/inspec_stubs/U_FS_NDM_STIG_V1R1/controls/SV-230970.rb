control 'SV-230970' do
  title 'Forescout must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'To verify the device is configured to terminate management sessions after 10 minutes of inactivity, verify the timeout value is configured.

1. Go to the Enterprise Manager Console.
2. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
3. Verify the "User Inactivity Timeout" check box is selected and the associated setting is set to "10 minutes".

If applicable, verify exceptions to this requirement are documented and signed.

If Forescout does not terminate the connection associated with an Enterprise Manager Console at the end of the session or after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Forescout is inherently designed to terminate upon exit or session disconnection, thus this part of the requirement does not have a fix. 

To configure Forescout to terminate the connection after 10 minutes of inactivity perform the following steps.
1. Go to the Enterprise Manager Console.
2. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
3. Ensure the "User In-activity Timeout" check box is selected and the associated setting is set to "10 minutes".'
  impact 0.7
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33900r603749_chk'
  tag severity: 'high'
  tag gid: 'V-230970'
  tag rid: 'SV-230970r615886_rule'
  tag stig_id: 'FORE-NM-000440'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-33873r603750_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
