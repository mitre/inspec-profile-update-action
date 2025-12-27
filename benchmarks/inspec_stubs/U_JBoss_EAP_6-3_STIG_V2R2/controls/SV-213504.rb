control 'SV-213504' do
  title 'JBoss must be configured to allow only the ISSM (or individuals or roles appointed by the ISSM) to select which loggable events are to be logged.'
  desc 'The JBoss server must be configured to select which personnel are assigned the role of selecting which loggable events are to be logged.
In JBoss, the role designated for selecting auditable events is the "Auditor" role.
The personnel or roles that can select loggable events are only the ISSM (or individuals or roles appointed by the ISSM).'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script to start the Command Line Interface (CLI). 
Connect to the server and authenticate.
Run the command:

For a Managed Domain configuration:
"ls host=master/server/<SERVERNAME>/core-service=management/access=authorization/role-mapping=Auditor/include="

For a Standalone configuration:
"ls /core-service=management/access=authorization/role-mapping=Auditor/include="

If the list of users in the Auditors group is not approved by the ISSM, this is a finding.'
  desc 'fix', 'Obtain documented approvals from ISSM, and assign the appropriate personnel into the "Auditor" role.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14727r296178_chk'
  tag severity: 'medium'
  tag gid: 'V-213504'
  tag rid: 'SV-213504r615939_rule'
  tag stig_id: 'JBOS-AS-000085'
  tag gtitle: 'SRG-APP-000090-AS-000051'
  tag fix_id: 'F-14725r296179_fix'
  tag 'documentable'
  tag legacy: ['SV-76723', 'V-62233']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
