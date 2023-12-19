control 'SV-215339' do
  title 'All AIX Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with that GID is subsequently created, the user may have unintended rights to the group.'
  desc 'check', %q(Verify that there are no GIDs referenced in "/etc/passwd" that are not defined in "/etc/group":

# cut -d: -f4 /etc/passwd
0
1
2
3
4
203
204

# cut -d: -f3 /etc/group
0
1
2
3
4
203
204

If there are GID's listed in the "/etc/passwd" file that are not listed in the "/etc/group" file, this is a finding.)
  desc 'fix', 'Add a group to the system for each GID referenced without a corresponding group by running "mkgroup" command.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16537r294468_chk'
  tag severity: 'medium'
  tag gid: 'V-215339'
  tag rid: 'SV-215339r508663_rule'
  tag stig_id: 'AIX7-00-003033'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16535r294469_fix'
  tag 'documentable'
  tag legacy: ['SV-101723', 'V-91625']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
