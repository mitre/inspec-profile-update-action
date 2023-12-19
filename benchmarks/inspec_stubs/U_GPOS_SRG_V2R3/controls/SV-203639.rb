control 'SV-203639' do
  title 'The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Verify the operating system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users). If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3764r557643_chk'
  tag severity: 'medium'
  tag gid: 'V-203639'
  tag rid: 'SV-203639r557645_rule'
  tag stig_id: 'SRG-OS-000104-GPOS-00051'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-3764r557644_fix'
  tag 'documentable'
  tag legacy: ['V-56753', 'SV-71013']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
