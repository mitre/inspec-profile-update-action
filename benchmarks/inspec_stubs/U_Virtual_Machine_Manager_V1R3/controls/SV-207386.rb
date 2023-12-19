control 'SV-207386' do
  title 'The VMM must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have the equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except for the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the VMM without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Verify the VMM uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7643r365568_chk'
  tag severity: 'medium'
  tag gid: 'V-207386'
  tag rid: 'SV-207386r378847_rule'
  tag stig_id: 'SRG-OS-000104-VMM-000500'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-7643r365569_fix'
  tag 'documentable'
  tag legacy: ['V-56963', 'SV-71223']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
