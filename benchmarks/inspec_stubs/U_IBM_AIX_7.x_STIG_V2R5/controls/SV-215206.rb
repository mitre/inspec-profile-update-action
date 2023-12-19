control 'SV-215206' do
  title 'The AIX /etc/passwd, /etc/security/passwd, and/or /etc/group files must not contain a plus (+) without defining entries for NIS+ netgroups or LDAP netgroups.'
  desc 'A plus (+) in system accounts files causes the system to lookup the specified entry using NIS. If the system is not using NIS, no such entries should exist.'
  desc 'check', 'Check system configuration files for plus (+) entries using the following commands:

# cat /etc/passwd | grep -v "^#" | grep "\\+" 

# cat /etc/security/passwd | grep -v "^#" | grep "\\+" 

# cat /etc/group | grep -v "^#" | grep "\\+" 

If the "/etc/passwd", "/etc/security/passwd", and/or "/etc/group" files contain a plus (+) and do not define entries for NIS+ netgroups or LDAP netgroups, this is a finding.'
  desc 'fix', 'Edit "/etc/passwd", "/etc/security/passwd", and/or "/etc/group" files and remove entries containing a plus (+).'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16404r294069_chk'
  tag severity: 'medium'
  tag gid: 'V-215206'
  tag rid: 'SV-215206r508663_rule'
  tag stig_id: 'AIX7-00-001047'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16402r294070_fix'
  tag 'documentable'
  tag legacy: ['V-91671', 'SV-101769']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
