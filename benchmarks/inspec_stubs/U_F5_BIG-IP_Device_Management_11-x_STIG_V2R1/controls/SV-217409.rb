control 'SV-217409' do
  title 'The BIG-IP appliance must be configured to terminate all network connections associated with a device management session at the end of the session, or the session must be configured to be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Verify the BIG-IP appliance is configured to terminate a connection associated with a device management session at the end of the session or after 10 minutes of inactivity. 

Navigate to the BIG-IP System manager >> System >> Preferences.

Verify that "Idle Time Before Automatic Logout" is set to 10 minutes or less.

If the BIG-IP appliance is not configured to terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18634r290781_chk'
  tag severity: 'high'
  tag gid: 'V-217409'
  tag rid: 'SV-217409r557520_rule'
  tag stig_id: 'F5BI-DM-000139'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-18632r290782_fix'
  tag 'documentable'
  tag legacy: ['SV-74597', 'V-60167']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
