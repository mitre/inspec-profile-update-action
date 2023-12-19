control 'SV-77475' do
  title 'Riverbed Optimization System (RiOS) must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 10 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Verify that RiOS is configured to terminate a device management session at the end of the session, or after 10 minutes of inactivity.

Navigate to the device CLI
Type: enable
Type: show web

Verify that "Inactivity Timeout:" is set to "10" minutes

-- or --

Navigate to the device Management Console
Navigate to Configure >> Security >> Web Settings

Verify that "Web Inactivity Timeout (minutes):" is set to "10"

If "Inactivity Timeout" or "Web Inactivity Timeout (minutes)" is not set to "10", this is a finding.'
  desc 'fix', 'Configure RiOS to terminate a device management session at the end of the session, or after 10 minutes of inactivity.

Navigate to the device CLI
Type: enable
Type: conf t
Type: web auto-logout 10
Type: write memory

-- or --

Navigate to the device Management Console
Navigate to Configure >> Security >> Web Settings
Set the value of "Web Inactivity Timeout (minutes):" to "10"

Click "Apply"
Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63737r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62985'
  tag rid: 'SV-77475r1_rule'
  tag stig_id: 'RICX-DM-000137'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-68903r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
