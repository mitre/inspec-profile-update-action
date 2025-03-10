control 'SV-213505' do
  title 'JBoss must be configured to initiate session logging upon startup.'
  desc 'Session logging activities are developed, integrated, and used in consultation with legal counsel in accordance with applicable federal laws, Executive Orders, directives, policies, or regulations.'
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
Connect to the server by typing "connect", authenticate as a user in the Superuser role and run the following command:

For a Managed Domain configuration:
"host=master/server/<SERVERNAME>/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"

For a Standalone configuration:
"/core-service=management/access=audit/logger=audit-log:write-attribute(name=enabled,value=true)"'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14728r296181_chk'
  tag severity: 'medium'
  tag gid: 'V-213505'
  tag rid: 'SV-213505r615939_rule'
  tag stig_id: 'JBOS-AS-000095'
  tag gtitle: 'SRG-APP-000092-AS-000053'
  tag fix_id: 'F-14726r296182_fix'
  tag 'documentable'
  tag legacy: ['SV-76725', 'V-62235']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
