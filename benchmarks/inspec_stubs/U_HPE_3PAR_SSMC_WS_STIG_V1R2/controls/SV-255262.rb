control 'SV-255262' do
  title 'SSMC web server must set an inactive timeout for shell sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed. 

Acceptable values are 5 minutes for high-value applications, 10 minutes for medium-value applications, and 20 minutes for low-value applications.'
  desc 'check', 'Verify that SSMC web server is configured to close inactive sessions after 10 minutes by doing the following:

1. Log on to the SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the command:

$ sudo /ssmc/bin/config_security.sh -o shell_session_idle_timeout -a status

Shell session idle timeout is configured to 600 seconds

If the shell session idle timeout status does not read as "configured to 600 seconds", this is a finding.'
  desc 'fix', 'Configure SSMC web server to close inactive shell sessions after 10 minutes by doing the following:

1. Log on to the SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Use vi to edit /ssmc/conf/security_config.properties file.

3. Uncomment and update "ssmc.shell.session.inactivity.timeout property" to "600 seconds". Save and exit.

4. Execute the following command:

$ sudo /ssmc/bin/config_security.sh -o shell_session_idle_timeout -a set

5. Terminate all open ssh sessions to SSMC appliance.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58875r869953_chk'
  tag severity: 'medium'
  tag gid: 'V-255262'
  tag rid: 'SV-255262r879673_rule'
  tag stig_id: 'SSMC-WS-010161'
  tag gtitle: 'SRG-APP-000295-WSR-000134'
  tag fix_id: 'F-58819r869954_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
