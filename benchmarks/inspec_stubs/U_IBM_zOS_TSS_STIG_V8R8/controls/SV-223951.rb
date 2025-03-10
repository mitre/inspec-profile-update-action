control 'SV-223951' do
  title 'IBM z/OS DASD management ACIDs must be properly defined to CA-TSS.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Refer to data obtained from the site installation identifying DASD maintenance ACIDs. 

If each DASD Maintenance ACID has batch Facility, this is not a finding.'
  desc 'fix', 'Define all batch ACIDs to the BATCH facility.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25624r516252_chk'
  tag severity: 'medium'
  tag gid: 'V-223951'
  tag rid: 'SV-223951r561402_rule'
  tag stig_id: 'TSS0-ES-000780'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25612r516253_fix'
  tag 'documentable'
  tag legacy: ['SV-107713', 'V-98609']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
