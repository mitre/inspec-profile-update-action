control 'SV-213498' do
  title 'The JBoss server must be configured with Role Based Access Controls.'
  desc 'By default, the JBoss server is not configured to utilize role based access controls (RBAC).  RBAC provides the capability to restrict user access to their designated management role, thereby limiting access to only the JBoss functionality that they are supposed to have.  Without RBAC, the JBoss server is not able to enforce authorized access according to role.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.

Run the following command:

For standalone servers:
"ls /core-service=management/access=authorization/"

For managed domain installations:
"ls /host=master/core-service=management/access=authorization/"

If the "provider" attribute is not set to "rbac", this is a finding.'
  desc 'fix', 'Run the following command.
<JBOSS_HOME>/bin/jboss-cli.sh -c -> connect -> cd /core-service=management/access-authorization :write-attribute(name=provider, value=rbac)

Restart JBoss.

Map users to roles by running the following command.  Upper-case words  are variables.

role-mapping=ROLENAME/include=ALIAS:add(name-USERNAME, type=USER ROLE)'
  impact 0.7
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14721r296160_chk'
  tag severity: 'high'
  tag gid: 'V-213498'
  tag rid: 'SV-213498r615939_rule'
  tag stig_id: 'JBOS-AS-000035'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-14719r296161_fix'
  tag 'documentable'
  tag legacy: ['SV-76717', 'V-62227']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
