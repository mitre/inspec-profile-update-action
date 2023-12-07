control 'SV-38740' do
  title 'The .rhosts, .shosts, hosts.equiv, shosts.equiv, /etc/passwd, /etc/shadow, and/or /etc/group files must not contain a plus (+) without defining entries for NIS+ netgroups or LDAP netgroups.'
  desc 'A plus (+) in system accounts files causes the system to lookup the specified entry using NIS or LDAP. If the system is not using NIS or LDAP, no such entries should exist.'
  desc 'check', 'Check system configuration files for plus (+) entries.

Procedure:
# find / -name .rhosts
# cat /<directorylocation>/.rhosts | grep -v "^#" | grep "\\+"

# find / -name .shosts
# cat /<directorylocation>/.shosts | grep -v "^#" | grep "\\+"

# find / -name hosts.equiv
# cat /<directorylocation>/hosts.equiv | grep -v "^#" | grep "\\+"

# find / -name shosts.equiv
# cat /<directorylocation>/shosts.equiv | grep -v "^#" | grep "\\+"

# cat /etc/passwd | grep -v "^#" | grep "\\+"
# cat /etc/security/passwd | grep -v "^#" | grep "\\+" 
# cat /etc/group | grep -v "^#" | grep "\\+"

If the .rhosts, .shosts, hosts.equiv, shosts.equiv, /etc/passwd, /etc/shadow, and/or /etc/group files contain a plus (+) and do not define entries for NIS+ netgroups or LDAP netgroups, this is a finding.'
  desc 'fix', 'Edit the .rhosts, .shosts, hosts.equiv, shosts.equiv, /etc/passwd, /etc/security/passwd, and/or /etc/group files and remove entries containing a plus (+).'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37175r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11987'
  tag rid: 'SV-38740r2_rule'
  tag stig_id: 'GEN001980'
  tag gtitle: 'GEN001980'
  tag fix_id: 'F-32455r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
