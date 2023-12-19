control 'SV-223873' do
  title 'IBM z/OS must have Certificate Name Filtering implemented with appropriate authorization and documentation.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'If certificate name filtering is in use, the ISSM should document each active filter rule and have written approval to use the rule.

Issue the following TSS command to list any certificate name filters defined to TSS:

TSS LIST(SDT) CERTMAP(ALL)

If there is nothing to list, this is not a finding.

NOTE: Certificate name filters are only valid when their Status is TRUST. Therefore, you may ignore filters with the NOTRUST status.

If certificate name filters are defined and they have a Status of TRUST, certificate name filtering is in use.

If certificate name filtering is in use and filtering rules have been documented and approved by the ISSM, this is not a finding.

If certificate name filtering is in use and filtering rules have not been documented and approved by the ISSM, this is a finding.'
  desc 'fix', 'Ensure any certificate name filtering rules in use are documented and approved by the ISSM.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25546r516018_chk'
  tag severity: 'medium'
  tag gid: 'V-223873'
  tag rid: 'SV-223873r561402_rule'
  tag stig_id: 'TSS0-CE-000030'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25534r516019_fix'
  tag 'documentable'
  tag legacy: ['V-98453', 'SV-107557']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
