control 'SV-251583' do
  title 'IDMS must support the implementation of an external security manager (ESM) to handle account management and user accesses, etc.'
  desc 'Internal security in a DBMS can be complex to implement and maintain with the increased possibility of no access or the wrong access to a needed resource. IDMS can be configured to use an ESM as the security repository allowing access rules to be added to already-known users.'
  desc 'check', 'When securing IDMS user IDs with an ESM, some preparation must be done in IDMS itself. Identify CA IDMS security domains (a set of DC systems and local mode applications sharing a single user catalog and SRTT). For a given security domain, logon to one DC system.

Issue DCPROFIL. If there is nothing specified for "Security System" and therefore no external security system being used, this is a finding.

Examine load module RHDCSRTT by executing CA IDMS utility "IDMSSRTD", or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476. 

If no TYPE=ENTRY with RESTYPE=SGON is found, this is a finding. 

If RESTYPE=SGON is secured internally, this is a finding.

Interrogate the security office and verify the ESM has the appropriate entries to secure the RESTYPE of SGON. If not, this is a finding.'
  desc 'fix', "The SRTT module must be coded to enable the desired security. When using an ESM, this could be done in the following manner:
 
#SECRTT TYPE=ENTRY,                          X
 RESTYPE=SGON,                                      X
 SECBY=EXTERNAL ,                               X
 EXTNAME=(RESNAME),                      X
 EXTCLS='CA@IDMS'

The RESNAME will be derived from the SYSTEM ID name in SYSGEN.

After making the above changes, ensure the ESM has the appropriate rules defined to give access to the desired users. For example, in a Top Secret environment where the SYSGEN SYSTEM ID is SYSO187:
TSS PER(user-id) CA@IDMS(SYSO187)

Also assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:

   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
   DCMT VARY NUCLEUS RELOAD"
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55018r807614_chk'
  tag severity: 'medium'
  tag gid: 'V-251583'
  tag rid: 'SV-251583r807616_rule'
  tag stig_id: 'IDMS-DB-000020'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-54972r807615_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
