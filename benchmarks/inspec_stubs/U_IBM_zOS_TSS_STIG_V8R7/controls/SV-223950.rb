control 'SV-223950' do
  title 'CA-TSS Batch ACID(s) submitted through RJE and NJE must be sourced.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Refer to data obtained from the site installation identifying batch type ACIDs. 

If all static batch ACIDs (ACIDs whose passwords never change) originating from a physical reader, RJE, or NJE are sourced to those readers such as (INTRDR, N12.IR, etc.) with the appropriate source Syntax, this is not a finding.'
  desc 'fix', 'Ensure that all static batch ACIDs (ACIDs whose passwords never change) originating from a physical reader, RJE, or NJE are sourced to those readers such as (INTRDR, N12.IR, etc.) with the appropriate source Syntax. Example: TSS ADD(batch-acid) SOURCE(device) 

Develop a plan of action and implement the changes as specified.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25623r516249_chk'
  tag severity: 'medium'
  tag gid: 'V-223950'
  tag rid: 'SV-223950r561402_rule'
  tag stig_id: 'TSS0-ES-000770'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25611r516250_fix'
  tag 'documentable'
  tag legacy: ['SV-107711', 'V-98607']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
