control 'SV-216189' do
  title 'Duplicate User IDs (UIDs) must not exist for users within the organization.'
  desc 'Users within the organization must be assigned unique UIDs for accountability and to ensure appropriate access protections.'
  desc 'check', 'The root role is required.

Check that there are no duplicate UIDs.

# logins -d

If output is produced, this is a finding.'
  desc 'fix', 'The root role is required.

Determine if there exists any users who share a common UID, and work with those users to determine the best course of action in accordance with site policy.
Change user account names and UID or delete accounts, so each account has a unique name and UID.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17427r372949_chk'
  tag severity: 'medium'
  tag gid: 'V-216189'
  tag rid: 'SV-216189r603268_rule'
  tag stig_id: 'SOL-11.1-070100'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-17425r372950_fix'
  tag 'documentable'
  tag legacy: ['V-48095', 'SV-60967']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
