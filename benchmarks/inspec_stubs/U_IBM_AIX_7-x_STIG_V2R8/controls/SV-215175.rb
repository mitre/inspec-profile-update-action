control 'SV-215175' do
  title 'All accounts on AIX system must have unique account names.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From the command prompt, run the following command to check that there are no duplicate account names:
# usrck -n ALL

If any duplicate account names are found, this is a finding.'
  desc 'fix', 'Edit user accounts to provide unique name for each account by editing the following files:
/etc/passwd
/etc/security/passwd
/etc/security/user
/etc/group'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16373r293976_chk'
  tag severity: 'high'
  tag gid: 'V-215175'
  tag rid: 'SV-215175r508663_rule'
  tag stig_id: 'AIX7-00-001008'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-16371r293977_fix'
  tag 'documentable'
  tag legacy: ['SV-101519', 'V-91421']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
