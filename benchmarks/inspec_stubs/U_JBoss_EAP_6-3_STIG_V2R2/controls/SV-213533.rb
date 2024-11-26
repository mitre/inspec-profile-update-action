control 'SV-213533' do
  title 'JBoss must utilize encryption when using LDAP for authentication.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

Application servers have the capability to utilize LDAP directories for authentication. If LDAP connections are not protected during transmission, sensitive authentication credentials can be stolen. When the application server utilizes LDAP, the LDAP traffic must be encrypted.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.

Run the following command:

For standalone servers:
"ls /socket-binding-group=standard-sockets/remote-destination-outbound-socket-binding=ldap_connection"

For managed domain installations:
"ls /socket-binding-group=<PROFILE>/remote-destination-outbound-socket-binding="

The default port for secure LDAP is 636.

If 636 or secure LDAP protocol is not utilized, this is a finding.'
  desc 'fix', 'Follow steps in section 11.8 - Management Interface Security in the JBoss_Enterprise_Application_Platform-6.3-Administration_and_Configuration_Guide-en-US document.

1. Create an outbound connection to the LDAP server.
2. Create an LDAP-enabled security realm.
3. Reference the new security domain in the Management Interface.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14756r296265_chk'
  tag severity: 'medium'
  tag gid: 'V-213533'
  tag rid: 'SV-213533r615939_rule'
  tag stig_id: 'JBOS-AS-000310'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag fix_id: 'F-14754r296266_fix'
  tag 'documentable'
  tag legacy: ['SV-76783', 'V-62293']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
