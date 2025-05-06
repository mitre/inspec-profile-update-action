control 'SV-213503' do
  title 'The JBoss server must generate log records for access and authentication events to the management interface.'
  desc 'Log records can be generated from various components within the JBoss application server.  The minimum list of logged events should be those pertaining to access and authentication events to the management interface as well as system startup and shutdown events.

By default, JBoss does not log management interface access but does provide a default file handler.  This handler needs to be enabled.  Configuring this setting meets several STIG auditing requirements.'
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
  tag check_id: 'C-14726r296175_chk'
  tag severity: 'medium'
  tag gid: 'V-213503'
  tag rid: 'SV-213503r615939_rule'
  tag stig_id: 'JBOS-AS-000080'
  tag gtitle: 'SRG-APP-000089-AS-000050'
  tag fix_id: 'F-14724r296176_fix'
  tag 'documentable'
  tag legacy: ['SV-76721', 'V-62231']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
