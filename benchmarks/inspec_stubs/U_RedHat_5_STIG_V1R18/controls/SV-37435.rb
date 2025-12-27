control 'SV-37435' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36048r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11987'
  tag rid: 'SV-37435r1_rule'
  tag stig_id: 'GEN001980'
  tag gtitle: 'GEN001980'
  tag fix_id: 'F-31292r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
