control 'SV-225245' do
  title 'Members of the Backup Operators group must be documented.'
  desc 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.  Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes.  Visibility of members of the Backup Operators group must be maintained.'
  desc 'check', 'If no accounts are members of the Backup Operators group, this is NA.

Any accounts that are members of the Backup Operators group, including application accounts, must be documented with the ISSO.  If documentation of accounts that are members of the Backup Operators group is not maintained this is a finding.'
  desc 'fix', 'Create the necessary documentation that identifies the members of the Backup Operators group.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26944r471077_chk'
  tag severity: 'medium'
  tag gid: 'V-225245'
  tag rid: 'SV-225245r569185_rule'
  tag stig_id: 'WN12-00-000009-01'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26932r471078_fix'
  tag 'documentable'
  tag legacy: ['SV-52156', 'V-1168']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
