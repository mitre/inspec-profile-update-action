control 'SV-213557' do
  title 'JBoss must be configured to generate log records for all account creations, modifications, disabling, and termination events.'
  desc 'The maintenance of user accounts is a key activity within the system to determine access and privileges.  Through changes to accounts, an attacker can create an account for persistent access, modify an account to elevate privileges, or terminate/disable an account(s) to cause a DoS for user(s).  To be able to track and investigate these actions, log records must be generated for any account modification functions.

Application servers either provide a local user store, or they can integrate with enterprise user stores like LDAP.  As such, the application server must be able to generate log records on account creation, modification, disabling, and termination.'
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
  tag check_id: 'C-14780r296337_chk'
  tag severity: 'medium'
  tag gid: 'V-213557'
  tag rid: 'SV-213557r615939_rule'
  tag stig_id: 'JBOS-AS-000720'
  tag gtitle: 'SRG-APP-000509-AS-000234'
  tag fix_id: 'F-14778r296338_fix'
  tag 'documentable'
  tag legacy: ['SV-76831', 'V-62341']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
