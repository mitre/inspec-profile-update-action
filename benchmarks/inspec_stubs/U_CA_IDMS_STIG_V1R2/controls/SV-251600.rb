control 'SV-251600' do
  title 'IDMS must use the ESM to generate auditable records for commands and utilities when DoD-defined auditable events occur.'
  desc %q(Audit records provide a tool to help research events within IDMS. IDMS itself does not produce audit records but, when external security is in place, records can be produced through the ESM.

IDMS relies on the ESM to log organization-defined auditable events. To ensure that all secure actions are logged, those actions must be defined to the IDMS Security Resource Type Table (SRTT) with a type of external security. When IDMS has to perform a given security check, it will defer to the ESM to determine the user's authorization. The auditing functionality of the ESM can be used to track the IDMS security calls. 

Some organization-defined auditable events are expected to be handled solely by the ESM. This would include requirements such as "successful and unsuccessful attempts to modify or delete privileges, security objects, security levels, or categories of information" as well as "account creation, modification, disablement, or termination."

For the audit logging of other organization-defined auditable events, IDMS requires RHDCSRTT security module set up to route requests for these events through the ESM. This will ensure that they are audited appropriately. The following resource types must be defined with SECBY type of EXTERNAL in the RHDCSRTT load module to achieve the appropriate level of audit logging. If there is not a resource type definition with a security type of EXTERNAL for the following resources, this is a finding.)
  desc 'check', %q(Examine load module IDMSCTAB by executing CA IDMS utility IDMSCTAD, or by issuing command "DCMT DISPLAY CTAB" while signed onto the CV and reviewing the output.

Note: This requires PTF SO08199. 

If there is execution of certain OCF/BCF commands that have not defined in the IDMSCTAB module using the #CTABGEN macro, this is a finding.

If these task codes are defined to the IDMSCTAB module but have not been defined for the related activities to the RHDCSRTT module, this is a finding.

If the execution of DCMT utility command codes is not defined in the IDMSUTAB module using the #UTABGEN macro, this is a finding.

Examine load module IDMSUTAB using CA IDMS utility IDMSUTAD, or by issuing command 'DCMT DISPLAY UTAB' while signed onto the CV, and reviewing the output.

Note: This requires PTF SO08527. 

If IDMSUTAB load module defined commands but has not defined the related activities to the RHDCSRTT module, this is a finding.

If any of the above tasks are completed from local mode, utilize a custom EXIT 14 to trigger a security check that will go through the ESM. If an EXIT 14 is not configured for each situation, this is a finding.)
  desc 'fix', 'If the IDMSUTAB load module needs to be updated to secure and audit the OCF/BCF commands, re-run the #UTABGEN macro to create an updated version. Here is an example of the syntax:
#UTABGEN (FORMAT,14,PRINTPAGE,14)

This syntax assigns the FORMAT and PRINTPAGE commands to activity 14, which can now be secured by the RHDCSRTT module.

If the IDMSCTAB load module needs updated to secure and audit the DCMT commands, update the #CTABGEN macro to create an updated version. Here is an example of the syntax:
#CTABGEN (B,2),(N022,B,N050,B)

This syntax assigns security label B to activity #2, then it assigns the tasks DCMT VARY MEMORY and DCMT VARY LOADLIB to security label B. With this definition, secure activity #2 appropriately in the RHDCSRTT module.'
  impact 0.7
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55035r807665_chk'
  tag severity: 'high'
  tag gid: 'V-251600'
  tag rid: 'SV-251600r807996_rule'
  tag stig_id: 'IDMS-DB-000200'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-54989r807666_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
