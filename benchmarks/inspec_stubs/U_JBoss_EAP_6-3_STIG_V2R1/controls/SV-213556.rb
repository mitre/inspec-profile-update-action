control 'SV-213556' do
  title 'JBoss must be configured to generate log records when concurrent logons from different workstations occur to the application server management interface.'
  desc 'Concurrent logons from different systems could possibly indicate a compromised account.  When concurrent logons are made from different workstations to the management interface, a log record needs to be generated.  This configuration setting provides forensic evidence that allows the system administrator to investigate access to the system and determine if the duplicate access was authorized or not.

JBoss provides a multitude of different log formats, and API calls that log access to the system.  If the default format and location is not used, the system admin must provide the configuration documentation and settings that show that this requirement is being met.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss. 
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder. 
Run the jboss-cli script to start the Command Line Interface (CLI). 
Connect to the server and authenticate. 
Run the command:

For a Managed Domain configuration:
"ls host=master/server/<SERVERNAME>/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"

For a Standalone configuration:
"ls /core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"

If "enabled" = false, this is a finding.'
  desc 'fix', 'Launch the jboss-cli management interface.
Connect to the server by typing "connect", authenticate as a user in the Superuser role, and run the following command:

For a Managed Domain configuration:
"host=master/server/<SERVERNAME>/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"

For a Standalone configuration:
"/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14779r296334_chk'
  tag severity: 'medium'
  tag gid: 'V-213556'
  tag rid: 'SV-213556r615939_rule'
  tag stig_id: 'JBOS-AS-000715'
  tag gtitle: 'SRG-APP-000506-AS-000231'
  tag fix_id: 'F-14777r296335_fix'
  tag 'documentable'
  tag legacy: ['SV-76829', 'V-62339']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
