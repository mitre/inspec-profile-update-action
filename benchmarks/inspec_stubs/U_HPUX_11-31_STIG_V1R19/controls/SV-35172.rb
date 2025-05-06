control 'SV-35172' do
  title 'SNMP communities, users, and passphrases must be changed from the default.'
  desc 'Whether active or not, default SNMP passwords, users, and passphrases must be changed to maintain security. If the service is running with the default authenticators, then anyone can gather data about the system and the network using the information to potentially compromise the integrity of the system or network(s).'
  desc 'check', 'Check the SNMP configuration for default passwords. Locate and examine the SNMP configuration.
# more /etc/SnmpAgent.d/snmpd.conf 

Alternatively:

# cat /etc/SnmpAgent.d/snmpd.conf | grep -i community

Identify any community names or user password configuration. If any community name or password is set to a default value such as public, private, snmp-trap, or password, or any value which does not meet DISA password requirements, this is a finding.'
  desc 'fix', 'Change the default passwords. To change them, edit the /etc/SnmpAgent.d/snmpd.conf file. Locate the line system-group-read-community which has a default password of public and make the password something more random (less guessable). Do the same for the lines reading system-group-write-community, read-community, write-community, trap, and trap-community. Read the information in the file carefully. The trap is defining who to send traps to, for instance, by default. It will not be a password, but the name of a host.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36606r1_chk'
  tag severity: 'high'
  tag gid: 'V-993'
  tag rid: 'SV-35172r1_rule'
  tag stig_id: 'GEN005300'
  tag gtitle: 'GEN005300'
  tag fix_id: 'F-31974r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000178']
  tag nist: ['IA-5 e']
end
