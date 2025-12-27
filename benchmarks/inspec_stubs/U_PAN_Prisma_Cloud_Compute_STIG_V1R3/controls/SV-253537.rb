control 'SV-253537' do
  title 'Prisma Cloud Compute must be configured with unique user accounts.'
  desc 'Sharing accounts, such as group accounts, reduces the accountability and integrity of Prisma Cloud Compute.'
  desc 'check', "Navigate to Prisma Cloud Compute Console's >> Manage >> Authentication >> Users tab. 

Review the accounts for uniqueness. If there are shared local accounts, this is a finding."
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's Manage >> Authentication >> Users tab.

Delete shared accounts and create a unique account for every Prisma Cloud Compute user.

Delete shared accounts:
- Click the three-dot menu. 
- Click "Delete" and confirm "Delete User".

Create a local user account where the local user account is unique:
- Click "+Add user".
- Complete the form and click "Save".)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56989r840447_chk'
  tag severity: 'medium'
  tag gid: 'V-253537'
  tag rid: 'SV-253537r879594_rule'
  tag stig_id: 'CNTR-PC-000590'
  tag gtitle: 'SRG-APP-000153-CTR-000375'
  tag fix_id: 'F-56940r840448_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
