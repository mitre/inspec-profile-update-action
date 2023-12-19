control 'SV-213494' do
  title 'HTTP management session traffic must be encrypted.'
  desc 'Types of management interfaces utilized by the JBoss EAP application server include web-based HTTP interfaces as well as command line-based management interfaces.  In the event remote HTTP management is required, the access must be via HTTPS.

This requirement is in conjunction with the requirement to isolate all management access to a restricted network.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss. Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder. 
Run the jboss-cli script. Connect to the server and authenticate. 

For a standalone configuration run the following command:
"ls /core-service=management/management-interface=http-interface"

If "secure-socket-binding"=undefined, this is a finding.

For a domain configuration run the following command:
"ls /host=master/core-service=management/management-interface=http-interface"

If "secure-port" is undefined, this is a finding.'
  desc 'fix', 'Follow the specific instructions in the Red Hat Security Guide for EAP version 6.3 to configure the management console for HTTPS.

This involves the following steps.
1. Create a keystore in JKS format.
2. Ensure the management console binds to HTTPS.
3. Create a new Security Realm.
4. Configure Management Interface to use new security realm.
5. Configure the management console to use the keystore.
6. Restart the EAP server.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14717r296148_chk'
  tag severity: 'medium'
  tag gid: 'V-213494'
  tag rid: 'SV-213494r615939_rule'
  tag stig_id: 'JBOS-AS-000010'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-14715r296149_fix'
  tag 'documentable'
  tag legacy: ['SV-76563', 'V-62073']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
