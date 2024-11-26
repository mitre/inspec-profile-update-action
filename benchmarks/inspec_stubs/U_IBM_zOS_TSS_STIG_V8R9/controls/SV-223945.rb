control 'SV-223945' do
  title 'The CA-TSS CPFTARGET Control Option value specified must be set to LOCAL.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the CPFTARGET Control Option value specified is not set to "LOCAL", this is a finding.'
  desc 'fix', 'Configure the CPFTARGET Control Option value specified set to LOCAL.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25618r516234_chk'
  tag severity: 'medium'
  tag gid: 'V-223945'
  tag rid: 'SV-223945r877786_rule'
  tag stig_id: 'TSS0-ES-000720'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25606r516235_fix'
  tag 'documentable'
  tag legacy: ['V-98597', 'SV-107701']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
