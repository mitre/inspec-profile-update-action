control 'SV-250336' do
  title 'The WebSphere Liberty Server must store only encrypted representations of user passwords.'
  desc 'WebSphere Liberty can either provide a local account store or integrate with enterprise account stores such as LDAP directories. If the application server stores application passwords in the server.xml configuration files, the application server must store encrypted representations of passwords rather than unencrypted, clear-text passwords.

The Liberty Application Server provides a SecurityUtility tool that can take a plain-text or encoded password and convert it to an encrypted password. This tool does not update the ${server.config.dir/server.xml file directly; a manual update of the server.xml is needed once the utility is run. 

It is imperative that administrators understand that the SecurityUtility tool must be run for each application password that is stored within the server.xml file.

'
  desc 'check', 'As a privileged user with file access to ${server.config.dir}/server.xml, review and ensure there are no clear-text passwords stored within the server.xml file.

If any passwords appear in plain text, or if any passwords start with {xor}, this is a finding.'
  desc 'fix', 'For additional information regarding the use of the SecurityUtility command, refer to IBM’s website: 
https://www.ibm.com/docs/en/was-liberty/base?topic=applications-securityutility-command

Create a new xml file with file permissions of 660.

File owner and group membership is the same as the WebSphere Liberty server user.

Add the following line to the new xml file:

<variable name="wlp.password.encryption.key" value="mysecret"/>

In the above, "mysecret" is the passphrase selected to create a cryptographic hash that represents the password.

Save the file to a secured location. Note the path and name, as it will be needed when updating server.xml.

Edit the server.xml file and add the following line:

<include location="/path/<xml file created>" />

For every unencrypted password in server.xml, run the following SecurityUtility command, which can be found in the Liberty Server install path:

SecurityUtility encode --encoding=aes 

This will prompt the user to enter the plain-text password stored within the server.xml file.

The SecurityUtility tool will generate an AES cryptographic hash of the password.

Copy and replace the plain-text password with the hashed value.

This must be done for every plain-text password in server.xml.

Restart the server by entering: 
server stop <server name>
server start <server name>'
  impact 0.7
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53771r795059_chk'
  tag severity: 'high'
  tag gid: 'V-250336'
  tag rid: 'SV-250336r795061_rule'
  tag stig_id: 'IBMW-LS-000440'
  tag gtitle: 'SRG-APP-000171-AS-000119'
  tag fix_id: 'F-53725r795060_fix'
  tag satisfies: ['SRG-APP-000171-AS-000119', 'SRG-APP-000428-AS-000265', 'SRG-APP-000429-AS-000157']
  tag 'documentable'
  tag cci: ['CCI-000196', 'CCI-002475', 'CCI-002476']
  tag nist: ['IA-5 (1) (c)', 'SC-28 (1)', 'SC-28 (1)']
end
