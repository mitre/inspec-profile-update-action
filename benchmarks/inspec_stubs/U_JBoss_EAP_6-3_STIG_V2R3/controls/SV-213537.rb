control 'SV-213537' do
  title 'Access to JBoss log files must be restricted to authorized users.'
  desc "If the application provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

Application servers must protect the error messages that are created by the application server. All application server users' accounts are used for the management of the server and the applications residing on the application server. All accounts are assigned to a certain role with corresponding access rights. The application server must restrict access to error messages so only authorized users may view them. Error messages are usually written to logs contained on the file system. The application server will usually create new log files as needed and must take steps to ensure that the proper file permissions are utilized when the log files are created."
  desc 'check', 'If the JBoss log folder is installed in the default location and AS-000133-JBOSS-00079 is not a finding, the log folders are protected and this requirement is not a finding.

By default, JBoss installs its log files into a sub-folder of the "jboss-eap-6.3" home folder. 
Using a UNIX like OS example, the default location for log files is:

JBOSS_HOME/standalone/log
JBOSS_HOME/domain/log

For a standalone configuration:
JBOSS_HOME/standalone/log/server.log"  Contains all server log messages, including server startup messages.

For a domain configuration:
JBOSS_HOME/domain/log/hostcontroller.log
Host Controller boot log. Contains log messages related to the startup of the host controller.

JBOSS_HOME/domain/log/processcontroller.log
Process controller boot log. Contains log messages related to the startup of the process controller.

JBOSS_HOME/domain/servers/SERVERNAME/log/server.log
The server log for the named server. Contains all log messages for that server, including server startup messages.

Log on with an OS user account with JBoss access and permissions.

Navigate to the "Jboss-eap-6.3" folder using the relevant OS commands for either a UNIX like OS or a Windows OS.

Examine the permissions of the JBoss logs folders.

Owner can be full access.
Group can be full access.
All others must be restricted.

If the JBoss log folder is world readable or world writeable, this is a finding.'
  desc 'fix', 'Configure file permissions on the JBoss log folder to protect from unauthorized access.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14760r296277_chk'
  tag severity: 'medium'
  tag gid: 'V-213537'
  tag rid: 'SV-213537r615939_rule'
  tag stig_id: 'JBOS-AS-000425'
  tag gtitle: 'SRG-APP-000267-AS-000170'
  tag fix_id: 'F-14758r296278_fix'
  tag 'documentable'
  tag legacy: ['SV-76791', 'V-62301']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
