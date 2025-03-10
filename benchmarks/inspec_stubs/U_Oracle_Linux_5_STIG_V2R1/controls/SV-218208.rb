control 'SV-218208' do
  title 'All accounts must be assigned unique User Identification Numbers (UIDs).'
  desc "Accounts sharing a UID have full access to each others' files.  This has the same effect as sharing a login.  There is no way to assure identification, authentication, and accountability because the system sees them as the same user. If the duplicate UID is 0, this gives potential intruders another privileged account to attack."
  desc 'check', 'Perform the following to ensure there are no duplicate UIDs:

# cut -d: -f3 /etc/passwd | uniq -d

If any duplicate UIDs are found, this is a finding.'
  desc 'fix', 'Edit user accounts to provide unique UIDs for each account.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19683r561410_chk'
  tag severity: 'medium'
  tag gid: 'V-218208'
  tag rid: 'SV-218208r603259_rule'
  tag stig_id: 'GEN000320'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-19681r561411_fix'
  tag 'documentable'
  tag legacy: ['V-762', 'SV-63255']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
