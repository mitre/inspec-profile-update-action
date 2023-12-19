control 'SV-216427' do
  title 'Duplicate UIDs must not exist for multiple non-organizational users.'
  desc 'Non-organizational users must be assigned unique UIDs for accountability and to ensure appropriate access protections.'
  desc 'check', 'The root role is required.

Check that there are no duplicate UIDs.

# logins -d

If output is produced, this is a finding.'
  desc 'fix', 'The root role is required.

Determine if there exists any users who share a common UID, and work with those users to determine the best course of action in accordance with site policy.
Change user account names and UID or delete accounts, so each account has a unique name and UID.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17663r371369_chk'
  tag severity: 'medium'
  tag gid: 'V-216427'
  tag rid: 'SV-216427r603267_rule'
  tag stig_id: 'SOL-11.1-070110'
  tag gtitle: 'SRG-OS-000121'
  tag fix_id: 'F-17661r371370_fix'
  tag 'documentable'
  tag legacy: ['V-48091', 'SV-60963']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
