control 'SV-213553' do
  title 'JBoss must be configured to generate log records when successful/unsuccessful logon attempts occur.'
  desc 'Logging the access to the application server allows the system administrators to monitor user accounts.  By logging successful/unsuccessful logons, the system administrator can determine if an account is compromised (e.g., frequent logons) or is in the process of being compromised (e.g., frequent failed logons) and can take actions to thwart the attack.

Logging successful logons can also be used to determine accounts that are no longer in use.'
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
  tag check_id: 'C-14776r296325_chk'
  tag severity: 'medium'
  tag gid: 'V-213553'
  tag rid: 'SV-213553r615939_rule'
  tag stig_id: 'JBOS-AS-000700'
  tag gtitle: 'SRG-APP-000503-AS-000228'
  tag fix_id: 'F-14774r296326_fix'
  tag 'documentable'
  tag legacy: ['SV-76823', 'V-62333']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
