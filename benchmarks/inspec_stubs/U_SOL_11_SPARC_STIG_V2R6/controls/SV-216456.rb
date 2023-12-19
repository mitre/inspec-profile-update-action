control 'SV-216456' do
  title 'SNMP communities, users, and passphrases must be changed from the default.'
  desc 'Whether active or not, default SNMP passwords, users, and passphrases must be changed to maintain security. If the service is running with the default authenticators, then anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s).'
  desc 'check', %q(The root role is required.

Check the SNMP configuration for default passwords.
Locate and examine the SNMP configuration.

Procedure:

Find any occurrences of the snmpd.conf file delivered with Solaris packages:

# pkg search -l -Ho path snmpd.conf | awk '{ print "/"$1 }'

# more [filename]

Identify any community names or user password configurations. If any community name or password is set to a default value, such as public, private, snmp-trap, or password, this is a finding.)
  desc 'fix', 'The root role is required.

Change the default snmpd.conf community passwords. To change them, locate the snmpd.conf file and edit it.

# pfedit [filename]

Locate the line system-group-read-community which has a default password of public and make the password something more random (less guessable). Make the same changes for the lines that read system- group-write-community, read-community, write-community, trap, and trap-community. Read the information in the file carefully. The trap is defining who to send traps to, for instance, by default. It is not a password, but the name of a host.'
  impact 0.7
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17692r793029_chk'
  tag severity: 'high'
  tag gid: 'V-216456'
  tag rid: 'SV-216456r793064_rule'
  tag stig_id: 'SOL-11.1-080160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17690r371457_fix'
  tag 'documentable'
  tag legacy: ['V-47995', 'SV-60867']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
