control 'SV-213500' do
  title 'Silent Authentication must be removed from the Default Application Security Realm.'
  desc 'Silent Authentication is a configuration setting that allows local OS users access to the JBoss server and a wide range of operations without specifically authenticating on an individual user basis.  By default $localuser is a Superuser. This introduces an integrity and availability vulnerability and violates best practice requirements regarding accountability.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.

Verify that Silent Authentication has been removed from the default Application security realm.
Run the following command.

For standalone servers, run the following command:
"ls /core-service=management/securityrealm=ApplicationRealm/authentication"

For managed domain installations, run the following command:
"ls /host=HOST_NAME/core-service=management/securityrealm=ApplicationRealm/authentication"

If "local" is returned, this is a finding.'
  desc 'fix', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder. 
Run the jboss-cli script.
Connect to the server and authenticate.

Remove the local element from the Application Realm.
For standalone servers, run the following command:
/core-service=management/securityrealm=
ApplicationRealm/authentication=local:remove

For managed domain installations, run the following command:
/host=HOST_NAME/core-service=management/securityrealm=
ApplicationRealm/authentication=local:remove'
  impact 0.7
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14723r296166_chk'
  tag severity: 'high'
  tag gid: 'V-213500'
  tag rid: 'SV-213500r615939_rule'
  tag stig_id: 'JBOS-AS-000045'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-14721r296167_fix'
  tag 'documentable'
  tag legacy: ['SV-76711', 'V-62221']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
