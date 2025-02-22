control 'SV-242244' do
  title 'The TippingPoint SMS must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'In the SMS client, ensure the SMS inactivity timeouts are configured.

1. Under Security, click Edit and Preferences. 
2. Under Client Preferences, if "Timeout client session after inactivity" is not checked or the Time is not set to 10 minutes, this is a finding.'
  desc 'fix', 'In the SMS client, ensure the SMS inactivity timeouts are configured. 

1. Under Security, click Edit and Preferences. 
2. Under Client Preferences, check the item "Timeout client session after inactivity" and ensure the Time is set to 10 minutes.'
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45519r710737_chk'
  tag severity: 'high'
  tag gid: 'V-242244'
  tag rid: 'SV-242244r754440_rule'
  tag stig_id: 'TIPP-NM-000320'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-45477r710738_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
