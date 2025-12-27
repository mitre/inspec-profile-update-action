control 'SV-38889' do
  title 'SNMP communities, users, and passphrases must be changed from the default.'
  desc 'Whether active or not, default SNMP passwords, users, and passphrases must be changed to maintain security. If the service is running with the default authenticators, then anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s).'
  desc 'check', 'Check the SNMP configuration for default passwords.

Locate and examine the SNMP configuration.
Procedure:
# find / -name "snmp*.conf" -print
# more <snmpd.conf> 

Identify any community names or user password configuration. If any community name or password is set to a default value such as public, private, snmp-trap, or password, or any value which does not meet DISA password requirements, this is a finding.'
  desc 'fix', 'Change the default passwords. To change them, locate the file /etc/snmpd.conf or the file /etc/snmpd3.conf. Edit the file. Locate the line system-group-read-community which has a default password of public and make the password something more random (less guessable). Do the same for the lines that read system-group-write-community, read-community, write-community, trap, and trap-community. Read the information in the file carefully. The trap is defining who to send traps to, for instance, by default. It is not a password, but the name of a host.'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37055r1_chk'
  tag severity: 'high'
  tag gid: 'V-993'
  tag rid: 'SV-38889r1_rule'
  tag stig_id: 'GEN005300'
  tag gtitle: 'GEN005300'
  tag fix_id: 'F-33134r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000178']
  tag nist: ['IA-5 e']
end
