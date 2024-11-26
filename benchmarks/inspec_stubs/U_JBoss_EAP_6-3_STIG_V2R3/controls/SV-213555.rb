control 'SV-213555' do
  title 'JBoss must be configured to generate log records that show starting and ending times for access to the application server management interface.'
  desc 'Determining when a user has accessed the management interface is important to determine the timeline of events when a security incident occurs.  Generating these events, especially if the management interface is accessed via a stateless protocol like HTTP, the log events will be generated when the user performs a logon (start) and when the user performs a logoff (end).  Without these events, the user and later investigators cannot determine the sequence of events and therefore cannot determine what may have happened and by whom it may have been done.

The generation of start and end times within log events allows the user to perform their due diligence in the event of a security breach.'
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
  tag check_id: 'C-14778r296331_chk'
  tag severity: 'medium'
  tag gid: 'V-213555'
  tag rid: 'SV-213555r615939_rule'
  tag stig_id: 'JBOS-AS-000710'
  tag gtitle: 'SRG-APP-000505-AS-000230'
  tag fix_id: 'F-14776r296332_fix'
  tag 'documentable'
  tag legacy: ['V-62337', 'SV-76827']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
