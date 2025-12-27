control 'SV-215176' do
  title 'All accounts on AIX must be assigned unique User Identification Numbers (UIDs) and must authenticate organizational and non-organizational users (or processes acting on behalf of these users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Lack of authentication and identification enables non-organizational users to gain access to the application or possibly other information systems and provides an opportunity for intruders to compromise resources within the application or information system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

'
  desc 'check', 'From the command prompt, run the following command to ensure there are no duplicate UIDs:

# usrck -n ALL

If any duplicate UIDs are found, this is a finding.'
  desc 'fix', 'Edit user accounts to provide unique names and UIDs for each account by editing the following files:

/etc/passwd
/etc/group
/etc/security/passwd
/etc/security/user'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16374r293979_chk'
  tag severity: 'high'
  tag gid: 'V-215176'
  tag rid: 'SV-215176r508663_rule'
  tag stig_id: 'AIX7-00-001009'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-16372r293980_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000121-GPOS-00062']
  tag 'documentable'
  tag legacy: ['V-91423', 'SV-101521']
  tag cci: ['CCI-000764', 'CCI-000804']
  tag nist: ['IA-2', 'IA-8']
end
