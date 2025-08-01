control 'SV-100341' do
  title 'Duplicate User IDs (UIDs) must not exist for users within the organization.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', %q(Verify that the SLES for vRealize contains no duplicate UIDs for organizational users by running the following command:

# awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If output is produced, this is a finding.)
  desc 'fix', 'Edit the file /etc/passwd and provide each organizational user account that has a duplicate UID with a unique UID.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89383r2_chk'
  tag severity: 'medium'
  tag gid: 'V-89691'
  tag rid: 'SV-100341r1_rule'
  tag stig_id: 'VRAU-SL-000680'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-96433r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
