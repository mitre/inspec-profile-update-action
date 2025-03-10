control 'SV-762' do
  title 'All accounts must be assigned unique User Identification Numbers (UIDs).'
  desc "Accounts sharing a UID have full access to each others' files.  This has the same effect as sharing a login.  There is no way to assure identification, authentication, and accountability because the system sees them as the same user. If the duplicate UID is 0, this gives potential intruders another privileged account to attack."
  desc 'check', "List any duplicate UIDs in /etc/passwd:
# cut -d':' -f3 /etc/passwd | uniq -d
This will show one copy of each duplicate UID."
  desc 'fix', 'Edit user accounts to provide unique UIDs for each account.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-762'
  tag rid: 'SV-762r2_rule'
  tag stig_id: 'GEN000320'
  tag gtitle: 'GEN000320'
  tag fix_id: 'F-24344r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
