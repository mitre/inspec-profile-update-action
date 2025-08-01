control 'SV-27068' do
  title 'All accounts must be assigned unique User Identification Numbers (UIDs).'
  desc "Accounts sharing a UID have full access to each others' files.  This has the same effect as sharing a login.  There is no way to assure identification, authentication, and accountability because the system sees them as the same user. If the duplicate UID is 0, this gives potential intruders another privileged account to attack."
  desc 'check', 'Perform the following to ensure there are no duplicate UIDs:

# cut -d: -f3 /etc/passwd | uniq -d

If any duplicate UIDs are found, this is a finding.'
  desc 'fix', 'Edit user accounts to provide unique UIDs for each account.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36104r2_chk'
  tag severity: 'medium'
  tag gid: 'V-762'
  tag rid: 'SV-27068r1_rule'
  tag stig_id: 'GEN000320'
  tag gtitle: 'GEN000320'
  tag fix_id: 'F-31350r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
