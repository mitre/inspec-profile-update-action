control 'SV-218345' do
  title 'The .rhosts, .shosts, hosts.equiv, shosts.equiv, /etc/passwd, /etc/shadow, and/or /etc/group files must not contain a plus (+) without defining entries for NIS+ netgroups.'
  desc 'A plus (+) in system accounts files causes the system to lookup the specified entry using NIS.  If the system is not using NIS, no such entries should exist.'
  desc 'check', 'Check system configuration files for plus (+) entries.

Procedure:
# find / -name .rhosts
# grep + /<directorylocation>/.rhosts

# find / -name .shosts
# grep + /<directorylocation>/.shosts

# find / -name hosts.equiv
# grep + /<directorylocation>/hosts.equiv

# find / -name shosts.equiv
# grep + /<directorylocation>/shosts.equiv

# grep + /etc/passwd
# grep + /etc/shadow
# grep + /etc/group

If the .rhosts, .shosts, hosts.equiv, shosts.equiv, /etc/passwd, /etc/shadow, and/or /etc/group files contain a plus (+) and do not define entries for NIS+ netgroups, this is a finding.'
  desc 'fix', 'Edit the .rhosts, .shosts, hosts.equiv, shosts.equiv, /etc/passwd, /etc/shadow, and/or /etc/group files and remove entries containing a plus (+).'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19820r554372_chk'
  tag severity: 'medium'
  tag gid: 'V-218345'
  tag rid: 'SV-218345r603259_rule'
  tag stig_id: 'GEN001980'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19818r554373_fix'
  tag 'documentable'
  tag legacy: ['V-11987', 'SV-63581']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
