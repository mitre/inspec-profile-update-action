control 'SV-48382' do
  title 'User-level information must be backed up per organization defined frequency consistent with recovery time and recovery point objectives.'
  desc 'Operating  system backup is a critical step in maintaining data assurance and availability.'
  desc 'check', 'Verify the organization has a process to backup user-level information to support recovery.  If it does not, this is a finding.'
  desc 'fix', 'Establish a process for backing up user-level information.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45051r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36733'
  tag rid: 'SV-48382r2_rule'
  tag stig_id: 'WN08-GE-000027'
  tag gtitle: 'WINGE-000027'
  tag fix_id: 'F-41513r1_fix'
  tag 'documentable'
  tag ia_controls: 'CODB-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
