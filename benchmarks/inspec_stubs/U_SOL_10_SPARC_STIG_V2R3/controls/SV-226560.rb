control 'SV-226560' do
  title 'The .rhosts, .shosts, hosts.equiv, shosts.equiv, /etc/passwd, /etc/shadow, and/or /etc/group files must not contain a plus (+) without defining entries for NIS+ netgroups.'
  desc "A plus (+) in system accounts' files causes the system to lookup the specified entry using NIS.  If the system is not using NIS, no such entries should exist."
  desc 'check', 'Check system configuration files for plus (+) entries.

Procedure:
# find / -name .rhosts -exec grep + {} \\;

# find / -name .shosts -exec grep + {} \\;

# find / -name hosts.equiv -exec grep + {} \\;

# find / -name shosts.equiv -exec grep + {} \\;


# grep + /etc/passwd
# grep + /etc/shadow
# grep + /etc/group

If the .rhosts, .shosts, hosts.equiv, shosts.equiv, /etc/passwd, /etc/shadow, and/or /etc/group files contain a plus (+) and do not define entries for NIS+ netgroups, this is a finding.'
  desc 'fix', 'Edit the .rhosts, .shosts, hosts.equiv, shosts.equiv, /etc/passwd, /etc/shadow, and/or /etc/group files and remove entries containing a plus (+).'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28721r483089_chk'
  tag severity: 'medium'
  tag gid: 'V-226560'
  tag rid: 'SV-226560r603265_rule'
  tag stig_id: 'GEN001980'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28709r483090_fix'
  tag 'documentable'
  tag legacy: ['V-11987', 'SV-12488']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
