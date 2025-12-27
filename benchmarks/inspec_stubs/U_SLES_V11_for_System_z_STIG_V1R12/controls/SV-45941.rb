control 'SV-45941' do
  title 'SNMP communities, users, and passphrases must be changed from the default.'
  desc 'Whether active or not, default SNMP passwords, users, and passphrases must be changed to maintain security. If the service is running with the default authenticators, then anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s).'
  desc 'check', 'Check the SNMP configuration for default passwords.

Procedure:
Examine the default install location /etc/snmp/snmpd.conf
or:
# find / -name snmpd.conf 
# more <snmpd.conf file> 

Identify any community names or user password configuration. If any community name or password is set to a default value such as "public", "private", "snmp-trap", or "password", or any value which does not meet DISA password requirements, this is a finding.'
  desc 'fix', 'Change the default passwords. To change them, locate the file snmpd.conf. Edit the file. Locate the line system-group-read-community which has a default password of “public” and make the password something more secure and less guessable. Do the same for the lines reading system-group-write-community, read-community, write-community, trap and trap-community. Read the information in the file carefully. The trap is defining who to send traps to, for instance, by default. It is not a password, but the name of a host.'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43238r1_chk'
  tag severity: 'high'
  tag gid: 'V-993'
  tag rid: 'SV-45941r1_rule'
  tag stig_id: 'GEN005300'
  tag gtitle: 'GEN005300'
  tag fix_id: 'F-39312r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000178']
  tag nist: ['IA-5 e']
end
