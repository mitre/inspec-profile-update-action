control 'SV-213502' do
  title 'JBoss management interfaces must be secured.'
  desc 'JBoss utilizes the concept of security realms to secure the management interfaces used for JBoss server administration.  If the security realm attribute is omitted or removed from the management interface definition, access to that interface is no longer secure.  The JBoss management interfaces must be secured.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.

Identify the management interfaces.  To identity the management interfaces, run the following command:

For standalone servers:
"ls /core-service=management/management-interface="

For managed domain installations:
"ls /host=HOST_NAME/core-service=management/management-interface="

By default, JBoss provides two management interfaces; they are named "NATIVE-INTERFACE" and "HTTP-INTERFACE".  The system may or may not have both interfaces enabled.  For each management interface listed as a result of the previous command, append the name of the management interface to the end of the following command.

For a standalone system:

"ls /core-service=management/management-interface=<MANAGEMENT INTERFACE NAME>"

For a managed domain:

"ls /host=HOST_NAME/core-service=management/management-interface=<MANAGEMENT INTERFACE NAME>"

If the "security-realm=" attribute is not associated with a management realm, this is a finding.'
  desc 'fix', 'Identify the security realm used for management of the system.  By default, this is called "Management Realm".

If a management security realm is not already available, reference the Jboss EAP 6.3 system administration guide for instructions on how to create a security realm for management purposes.  Create the management realm, and assign authentication and authorization access restrictions to the management realm.

Assign the management interfaces to the management realm.'
  impact 0.7
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14725r296172_chk'
  tag severity: 'high'
  tag gid: 'V-213502'
  tag rid: 'SV-213502r615939_rule'
  tag stig_id: 'JBOS-AS-000075'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-14723r296173_fix'
  tag 'documentable'
  tag legacy: ['SV-76719', 'V-62229']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
