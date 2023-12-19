control 'SV-217163' do
  title 'The SUSE operating system must not have duplicate User IDs (UIDs) for interactive users.'
  desc 'To assure accountability and prevent unauthenticated access, interactive users must be identified and authenticated to prevent potential misuse and compromise of the system.

Interactive users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Interactive users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

'
  desc 'check', %q(Verify the SUSE operating system contains no duplicate UIDs for interactive users.

Check that the SUSE operating system contains no duplicate UIDs for interactive users by running the following command:

# awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If output is produced, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to contain no duplicate UIDs for interactive users.

Edit the file "/etc/passwd" and provide each interactive user account that has a duplicate UID with a unique UID.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18391r369645_chk'
  tag severity: 'medium'
  tag gid: 'V-217163'
  tag rid: 'SV-217163r603262_rule'
  tag stig_id: 'SLES-12-010640'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-18389r369646_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000121-GPOS-00062']
  tag 'documentable'
  tag legacy: ['SV-91873', 'V-77177']
  tag cci: ['CCI-000764', 'CCI-000804']
  tag nist: ['IA-2', 'IA-8']
end
