control 'SV-227538' do
  title 'The /usr/aset/masters/uid_aliases must be empty.'
  desc 'If uid_aliases has entries, users may not be properly identified in ASET records.'
  desc 'check', '# more /usr/aset/masters/uid_aliases

If the /usr/aset/masters/uid_aliases file is not empty or all contents are not commented out, this is a finding.'
  desc 'fix', 'Empty or comment out the entries in the uid_aliases file.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29700r488144_chk'
  tag severity: 'medium'
  tag gid: 'V-227538'
  tag rid: 'SV-227538r603266_rule'
  tag stig_id: 'GEN000000-SOL00140'
  tag gtitle: 'SRG-OS-000016'
  tag fix_id: 'F-29688r488145_fix'
  tag 'documentable'
  tag legacy: ['V-4312', 'SV-4312']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
