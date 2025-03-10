control 'SV-223946' do
  title 'CA-TSS User ACIDs and Control ACIDs must have the NAME field completed.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST (ACIDs) DATA (BASIC)

If any ACID does not have the "NAME" field completed, this is a finding.'
  desc 'fix', 'Review all ACID definitions and ensure the NAME field is completed. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement.'
  impact 0.3
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25619r516237_chk'
  tag severity: 'low'
  tag gid: 'V-223946'
  tag rid: 'SV-223946r561402_rule'
  tag stig_id: 'TSS0-ES-000730'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25607r516238_fix'
  tag 'documentable'
  tag legacy: ['SV-107703', 'V-98599']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
