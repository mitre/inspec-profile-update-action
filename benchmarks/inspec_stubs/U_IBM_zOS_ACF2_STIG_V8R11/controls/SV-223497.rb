control 'SV-223497' do
  title 'CA-ACF2 defined user accounts must uniquely identify system users.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

'
  desc 'check', 'Obtain a list of all userids that are shared among multiple users (i.e., not uniquely identified system users).

If there are no shared userids on this domain, this is not a finding.

If there are shared userids on this domain, this is a finding.

NOTE: Userids should be able to be traced back to a current DD Form 2875 or a Vendor Requirement (example: A Started Task).'
  desc 'fix', 'Identify user accounts defined to the ESM that are being shared among multiple users. This may require interviews with appropriate system-level support personnel. Remove the shared user accounts from the ESM.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25170r504591_chk'
  tag severity: 'medium'
  tag gid: 'V-223497'
  tag rid: 'SV-223497r533198_rule'
  tag stig_id: 'ACF2-ES-000790'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25158r504592_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000121-GPOS-00062', 'SRG-OS-000125-GPOS-00065']
  tag 'documentable'
  tag legacy: ['V-97693', 'SV-106797']
  tag cci: ['CCI-000764', 'CCI-000804', 'CCI-000877']
  tag nist: ['IA-2', 'IA-8', 'MA-4 c']
end
