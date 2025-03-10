control 'SV-251599' do
  title 'IDMS must use the ESM to generate auditable records for resources when DoD-defined auditable events occur.'
  desc %q(Audit records provide a tool to help research events within IDMS. IDMS does not produce audit records, but when using external security, records can be produced through the ESM.

IDMS relies on the ESM to log organization-defined auditable events. To ensure that all secure actions are logged, those actions  must be defined to the IDMS Security Resource Type Table (SRTT) with a type of external security. When IDMS has to perform a given security check, it will defer to the ESM to determine the user's authorization. The auditing functionality of the ESM can be used to track the IDMS security calls.

Some organization-defined auditable events are expected to be handled solely by the ESM. This would include requirements such as "successful and unsuccessful attempts to modify or delete privileges, security objects, security levels, or categories of information" as well as "account creation, modification, disablement, or termination."

For the audit logging of other organization-defined auditable events, IDMS requires RHDCSRTT security module set up to route requests for these events through the ESM. This will ensure that they are audited appropriately. The following resource types must be defined with SECBY type of EXTERNAL in the RHDCSRTT load module to achieve the appropriate level of audit logging. 

If there is not a resource type definition with a security type of EXTERNAL for the following resources, this is a finding.)
  desc 'check', 'Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV and reviewing the output.

Note: This requires PTFs SO07995 and SO09476. 

If the ESM specification does not match the RHDCSRTT entry, this is a finding.

Validate each of the following listed entries:
Access Actions such as login – Resource type SGON
Privileged system access – Resource types SYST, DB, DMCL, DBTB
Privileged object access – Resource types SLOD, SACC, QUEU
Privileged program access – Resource type TASK, SPGM

If any are not secured externally, this is a finding.'
  desc 'fix', 'If some of the resource types were not defined to the #SECRTT with SECBY=EXTERNAL, update the #SECRTT security module to include the appropriate definitions.

Access Actions such as login – Resource type SGON
Privileged system access – Resource types SYST, DB, DMCL, DBTB 
Privileged object access – Resource types SLOD, SACC, QUEU
Privileged program access – Resource type TASK, SPGM

To update the #SECRTT entries, change any invalid definitions of SECBY=INTERNAL to SECBY=EXTERNAL for the resources listed above. If any of the resource types are missing, add them. Once the updates are complete, recompile the RHDCSRTT module. Then confirm that the resource types are referenced appropriately by the external security manager.'
  impact 0.7
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55034r808353_chk'
  tag severity: 'high'
  tag gid: 'V-251599'
  tag rid: 'SV-251599r808354_rule'
  tag stig_id: 'IDMS-DB-000190'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-54988r807663_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
