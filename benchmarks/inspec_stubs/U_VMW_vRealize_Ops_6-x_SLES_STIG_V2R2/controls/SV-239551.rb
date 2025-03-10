control 'SV-239551' do
  title 'Duplicate User IDs (UIDs) must not exist for users within the organization.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of SLES for vRealize.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', %q(Verify that SLES for vRealize contains no duplicate UIDs for organizational users by running the following command:

# awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If output is produced, this is a finding.)
  desc 'fix', 'Edit the file "/etc/passwd" and provide each organizational user account that has a duplicate UID with a unique UID.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42784r662102_chk'
  tag severity: 'medium'
  tag gid: 'V-239551'
  tag rid: 'SV-239551r662104_rule'
  tag stig_id: 'VROM-SL-000660'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-42743r662103_fix'
  tag 'documentable'
  tag legacy: ['SV-99223', 'V-88573']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
