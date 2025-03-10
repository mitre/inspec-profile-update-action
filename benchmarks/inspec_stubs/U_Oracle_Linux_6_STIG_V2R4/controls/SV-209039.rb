control 'SV-209039' do
  title 'All public directories must be owned by a system account.'
  desc 'Allowing a user account to own a world-writable directory is undesirable because it allows the owner of that directory to remove or replace any files that may be placed in the directory by other users.'
  desc 'check', 'The following command will discover and print world-writable directories that are not owned by a system account, given the assumption that only system accounts have a uid lower than 500. Run it once for each local partition [PART]: 

# find [PART] -xdev -type d -perm -0002 -uid +500 -print

If there is output, this is a finding.'
  desc 'fix', 'All directories in local partitions which are world-writable should be owned by root or another system account.

If any world-writable directories are not owned by a system account, this should be investigated.

Following this, the files should be deleted or assigned to an appropriate group.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9292r357902_chk'
  tag severity: 'low'
  tag gid: 'V-209039'
  tag rid: 'SV-209039r603263_rule'
  tag stig_id: 'OL6-00-000337'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9292r357903_fix'
  tag 'documentable'
  tag legacy: ['SV-65633', 'V-51423']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
