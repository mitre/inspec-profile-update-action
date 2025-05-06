control 'SV-255247' do
  title 'SSMC must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level, and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

'
  desc 'check', 'Verify that SSMC web server is configured to close inactive sessions after 10 minutes by doing the following:

1. Log on to the SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the command:

$ grep ^server.session.timeout /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties

server.session.timeout=10

If the value is not set to 10 minutes, this is a finding.'
  desc 'fix', 'Configure SSMC web server to close inactive sessions after 10 minutes by doing the following:

1. Log on to the SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Use vi to edit /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties file.

3. Uncomment and update server.session.timeout property to 10 minutes (default is 15). Save and exit.

4. Type "config_appliance" to return to TUI. Restart (stop and start) SSMC services using TUI menu option 2.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58860r869889_chk'
  tag severity: 'medium'
  tag gid: 'V-255247'
  tag rid: 'SV-255247r869891_rule'
  tag stig_id: 'SSMC-OS-020010'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-58804r869890_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
