control 'SV-256083' do
  title 'The Riverbed NetProfiler must be configured to terminate all sessions and network connections when nonlocal device maintenance is completed.'
  desc 'If a device management session or connection remains open after management is completed, it may be hijacked by an attacker and used to compromise or damage the network device.

Nonlocal device management and diagnostic activities are conducted by individuals communicating through an external network (e.g., the internet) or an internal network. 

Logging out of NetProfiler ends the session with NetProfiler. It does not close sessions with the SAML identity provider involved with the initial authentication process or those for any other Riverbed product involved in cross-product drill downs. Therefore, it is recommended to close all browser tabs and close the browser when finished accessing NetProfiler authentication.'
  desc 'check', 'Ask if the system administrators are trained to log out and close browsers upon finishing with management sessions.

Verify the inactivity timeout is set.

Go to Configuration >> Appliance Security >> Password Security. 

Under "Inactivity Timeout", verify the "Enable Maximum Inactivity Timeout" box is checked and the timer is set for 10 minutes. 

If the inactivity timeout is not enabled, and/or the timer is not set to 10 minutes, this is a finding.'
  desc 'fix', 'To ensure all management sessions or connections are closed upon termination or abort, system administrators must be trained to log out after each session, the inactivity timeout must be configured, and all browser sessions must be closed.

Go to Configuration >> Appliance Security >> Password Security. 

Under "Inactivity Timeout", check the "Enable Maximum Inactivity Timeout" box and set the timer for 10 minutes.

NOTE: Logging out of NetProfiler ends the session with NetProfiler. It does not close sessions with the SAML identity provider involved with the initial authentication process or those for any other Riverbed product involved in cross-product drill downs. Therefore, it is recommended to close all browser tabs and close the browser when finished accessing NetProfiler authentication.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59757r882755_chk'
  tag severity: 'medium'
  tag gid: 'V-256083'
  tag rid: 'SV-256083r882757_rule'
  tag stig_id: 'RINP-DM-000041'
  tag gtitle: 'SRG-APP-000186-NDM-000266'
  tag fix_id: 'F-59700r882756_fix'
  tag 'documentable'
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
