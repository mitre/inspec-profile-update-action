control 'SV-250996' do
  title 'MobileIron Sentry must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirement.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'The MobileIron Sentry System Manager has two interfaces, a CLI restricted shell and web-based GUI. In the MobileIron Sentry MICS portal, verify that the MobileIron Sentry CLI timeout is set to 10 minutes.

1. Log in to MobileIron Sentry.
2. Go to Settings >> CLI.
3. Within CLI Configuration, verify the CLI Session Timeout(minutes) is set to greater than 10 minutes.

If the CLI Session Timeout(minutes) is not set to greater than 10 minutes, this is a finding.'
  desc 'fix', 'Configure the Sentry to terminate the connection associated with a device management session at the end of the session or after 10 minutes of inactivity.

1. Log in to MobileIron Sentry.
2. Go to Settings >> CLI.
3. Within CLI Configuration, input "10" for CLI Session Timeout(minutes).
4. Click "Apply".'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54431r802208_chk'
  tag severity: 'high'
  tag gid: 'V-250996'
  tag rid: 'SV-250996r802210_rule'
  tag stig_id: 'MOIS-ND-000550'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-54385r802209_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
