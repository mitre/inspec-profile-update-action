control 'SV-213554' do
  title 'JBoss must be configured to generate log records for privileged activities.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Privileged activities would occur through the management interface.  This interface can be web-based or can be command line utilities.  Whichever method is utilized by the application server, these activities must be logged.'
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
  tag check_id: 'C-14777r296328_chk'
  tag severity: 'medium'
  tag gid: 'V-213554'
  tag rid: 'SV-213554r615939_rule'
  tag stig_id: 'JBOS-AS-000705'
  tag gtitle: 'SRG-APP-000504-AS-000229'
  tag fix_id: 'F-14775r296329_fix'
  tag 'documentable'
  tag legacy: ['SV-76825', 'V-62335']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
