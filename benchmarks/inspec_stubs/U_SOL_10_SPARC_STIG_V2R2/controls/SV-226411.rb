control 'SV-226411' do
  title 'The /usr/aset/masters/uid_aliases must be empty.'
  desc 'If uid_aliases has entries, users may not be properly identified in ASET records.'
  desc 'check', '# more /usr/aset/masters/uid_aliases

If the /usr/aset/masters/uid_aliases file is not empty or all contents are not commented out, this is a finding.'
  desc 'fix', 'Empty or comment out the entries in the uid_aliases file.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28572r482591_chk'
  tag severity: 'medium'
  tag gid: 'V-226411'
  tag rid: 'SV-226411r603265_rule'
  tag stig_id: 'GEN000000-SOL00140'
  tag gtitle: 'SRG-OS-000016'
  tag fix_id: 'F-28560r482592_fix'
  tag 'documentable'
  tag legacy: ['SV-4312', 'V-4312']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
