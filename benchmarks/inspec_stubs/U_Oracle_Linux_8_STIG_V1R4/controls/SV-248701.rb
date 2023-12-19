control 'SV-248701' do
  title 'OL 8 duplicate User IDs (UIDs) must not exist for interactive users.'
  desc 'To ensure accountability and prevent unauthenticated access, interactive users must be identified and authenticated to prevent potential misuse and compromise of the system. 
 
Interactive users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Interactive users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 
 
1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
 
2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

'
  desc 'check', %q(Verify that OL 8 contains no duplicate UIDs for interactive users with the following command: 
 
$ sudo awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd 
 
If output is produced and the accounts listed are interactive user accounts, this is a finding.)
  desc 'fix', 'Edit the file "/etc/passwd" and provide each interactive user account that has a duplicate UID with a unique UID.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52135r779667_chk'
  tag severity: 'medium'
  tag gid: 'V-248701'
  tag rid: 'SV-248701r779669_rule'
  tag stig_id: 'OL08-00-020240'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-52089r779668_fix'
  tag satisfies: ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000104-GPOS-00051', 'SRG-OS-000121-GPOS-00062']
  tag 'documentable'
  tag cci: ['CCI-000135', 'CCI-000764', 'CCI-000804']
  tag nist: ['AU-3 (1)', 'IA-2', 'IA-8']
end
