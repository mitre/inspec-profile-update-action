control 'SV-251613' do
  title 'DBMS authentication using passwords must be avoided.'
  desc 'Passwords that are easy to guess open a vulnerability allowing an unauthorized user to potentially gain access to the DBMS. IDMS uses the External Security Manager (ESM) to enforce complexity and lifetime standards.'
  desc 'check', 'Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476.

Find the entry for RESTYPE=SGON. If no SGON entry exists, this is a finding. If found, verify that the entry has SECBY=EXTERNAL. If it does not, this is a finding.

Verify that the ESM entry for the externally secured "SGON" resource is correctly configured for the external resource class and the external name of the "SGON" SRTT entry.

For local batch jobs that access database files, if there is no ESM security defined for the users submitting the jobs or securing the database datasets, this is a finding.'
  desc 'fix', "The SRTT module must be coded to secure the system. When using an ESM, this could be done in the following manner:

               #SECRTT TYPE=ENTRY,                                   X
                          RESTYPE=SGON,                                   X
                          SECBY=EXTERNAL ,                               X
                         EXTNAME=(RESTYPE,RESNAME),        X
                         EXTCLS='CA@IDMS'

EXTCLS maps the CA IDMS resource type to the resource class defined in the ESM. The EXTNAME defines the format of the resource name defined to the ESM.

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:

   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
   DCMT VARY NUCLEUS RELOAD

Ensure the ESM has a corresponding entry to give access to the desired users. For instance, in Top Secret:
TSS PER(user_id) CA@IDMS(SGON.the_extname)

In ACF2:
$KEY(SGON.the_extname) TYPE(CA@IDMS) 
 UID(user_id) ALLOW

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:

DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
DCMT VARY NUCLEUS RELOAD"
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55048r807704_chk'
  tag severity: 'medium'
  tag gid: 'V-251613'
  tag rid: 'SV-251613r807706_rule'
  tag stig_id: 'IDMS-DB-000330'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-55002r807705_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
