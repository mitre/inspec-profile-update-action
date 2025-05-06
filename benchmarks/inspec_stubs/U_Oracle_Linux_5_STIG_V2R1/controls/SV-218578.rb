control 'SV-218578' do
  title 'SNMP communities, users, and passphrases must be changed from the default.'
  desc 'Whether active or not, default SNMP passwords, users, and passphrases must be changed to maintain security. If the service is running with the default authenticators, then anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s).'
  desc 'check', 'Check the SNMP configuration for default passwords.

Procedure:
Examine the default install location /etc/snmp/snmpd.conf
or:
# find / -name snmpd.conf 
# more <snmpd.conf file> 

Identify any community names or user password configuration. If any community name or password is set to a default value such as "public", "private", "snmp-trap", or "password", or any value which does not meet DISA password requirements, this is a finding.'
  desc 'fix', 'Change the default passwords.
To change them, locate the file snmpd.conf.

Edit the file.
 
Locate the line system-group-read-community which has a default password of "public" and make the password something more secure and less guessable.

Do the same for the lines reading system-group-write-community, read-community, write-community, trap and trap-community. 

Read the information in the file carefully. The trap is defining who to send traps to, for instance, by default. It is not a password, but the name of a host.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20053r562810_chk'
  tag severity: 'high'
  tag gid: 'V-218578'
  tag rid: 'SV-218578r603259_rule'
  tag stig_id: 'GEN005300'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20051r562811_fix'
  tag 'documentable'
  tag legacy: ['V-993', 'SV-63371']
  tag cci: ['CCI-000178', 'CCI-000366']
  tag nist: ['IA-5 e', 'CM-6 b']
end
