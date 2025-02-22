control 'SV-213539' do
  title 'The application server must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Restricting non-privileged users also prevents an attacker who has gained access to a non-privileged account, from elevating privileges, creating accounts, and performing system checks and maintenance.'
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

Map users to roles by running the following command.  Upper-case words are variables.

role-mapping=ROLENAME/include=ALIAS:add(name-USERNAME, type=USER ROLE)'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14762r296283_chk'
  tag severity: 'medium'
  tag gid: 'V-213539'
  tag rid: 'SV-213539r615939_rule'
  tag stig_id: 'JBOS-AS-000475'
  tag gtitle: 'SRG-APP-000340-AS-000185'
  tag fix_id: 'F-14760r296284_fix'
  tag 'documentable'
  tag legacy: ['SV-76795', 'V-62305']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
