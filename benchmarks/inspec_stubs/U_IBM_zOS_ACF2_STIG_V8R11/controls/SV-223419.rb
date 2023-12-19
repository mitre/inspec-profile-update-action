control 'SV-223419' do
  title 'IBM z/OS Certificate Name Filtering must be implemented with appropriate authorization and documentation.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'If Certificate Name Filtering is in use, collect documentation describing each active filter rule and written approval from the ISSM to use the rule.

Issue the following ACF2 commands to list the certificate name filters defined to ACF2:
SET CONTROL(GSO)
SHOW CERTMAP

If no CERTMAP FILTERING TABLES are present, this not a finding.

NOTE: Certificate name filters are only valid when their Status is TRUST. Therefore, you may ignore filters with the NOTRUST status.

If CERTMAP FILTERING TABLES are present and certificate name filters have a Status of TRUST, certificate name filtering is in use.

If Certificate Name Filtering is in use and filtering rules have been documented and approved by the ISSM, this is not a finding.

If Certificate Name Filtering is in use and filtering rules have not been documented and approved by the ISSM, this is a finding.'
  desc 'fix', 'Define any Certificate Name Filtering rules when required with documentation and approval by the ISSM.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25092r500387_chk'
  tag severity: 'medium'
  tag gid: 'V-223419'
  tag rid: 'SV-223419r533198_rule'
  tag stig_id: 'ACF2-CE-000010'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25080r500388_fix'
  tag 'documentable'
  tag legacy: ['V-97535', 'SV-106639']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
