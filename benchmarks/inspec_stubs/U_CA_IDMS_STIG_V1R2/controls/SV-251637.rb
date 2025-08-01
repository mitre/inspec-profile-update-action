control 'SV-251637' do
  title 'IDMS must prevent unauthorized users from executing certain privileged commands that can be used to change the runtime IDMS environment.'
  desc 'Ensure that a subset DCMT commands are  secured so that only those with the appropriate authority are able to execute them. Access to these DCMT commands can allow a user to circumvent defined security policies and procedures, and to make other detrimental changes to the CV environment.'
  desc 'check', 'Verify that the following DCMT commands are protected for use by the appropriate users:

DCMT DISPLAY MEMORY                             
DCMT VARY DYNAMIC PROGRAM
DCMT VARY DYNAMIC TASK
DCMT VARY LOADLIB
DCMT VARY MEMORY
DCMT VARY NUCLEUS
DCMT VARY PROGRAM
DCMT VARY RUN UNIT
DCMT VARY SYSGEN

Examine load module IDMSCTAB using CA IDMS utility IDMSCTAD, or by issuing command "DCMT DISPLAY CTAB" while signed onto the CV and reviewing the output. 

Note: This requires PTF SO08199.

If the command codes for the commands listed above are not present in the output, this is a finding. 

Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV and reviewing the output.

Note: This requires PTFs SO07995 and SO09476.

Review the output to determine if there are ACTI entries to secure the above commands. Activity numbers are assigned in IDMSCTAB and used in the SRTT formats for the external resource name. 

Contact the security office if the resource access is not restricted to only users authorized in the site security plan. 

If the resource access is not restricted to only users authorized in the site security plan, this is a finding.'
  desc 'fix', "The SRTT must contain one or more entries to enable the external security of RESTYPE=ACTI. For example:
 
#SECRTT TYPE=ENTRY,RESTYPE=ACTI, SECBY=EXTERNAL,      EXTCLS='CA@IDMS',EXTNAME=(SYST,ACTIVITY)       

Update the source for IDMSCTAB as needed. 

This example #CTABGEN entry secures the DCMT commands listed in the check and assigns a task number to each:

CTAB  TITLE 'GENERATE DCMT SECURITY TABLE'                              
         #CTABGEN LOGIN=YES,                                           X
               (A,1,B,2,C,3,D,4,E,5,F,6,G,7,H,8,I,9),                  X
               (N022,A),                DCMT DISPLAY MEMORY            X
               (N046001,B),             DCMT VARY DYNAMIC PROGRAM      X
               (N046002,C),             DCMT VARY DYNAMIC TASK         X
               (N050,D),                DCMT VARY LOADLIB              X
               (N033,E),                DCMT VARY MEMORY               X
               (N063,F),                DCMT VARY NUCLEUS              X
               (N025,G),                DCMT VARY PROGRAM              X
               (N073,H),                DCMT VARY RUN UNIT             X
               (N095,I)                 DCMT VARY SYSGEN                
         END                                                            

The ACTIVITY passed to the ESM will be the first up to five  bytes of the application name followed by the three-byte activity number or, using the above example, DCMT009 for a DCMT VARY SYSGEN command.
 
After making the above changes, IDMSCTAB and RHDCSRTT must be reassembled and relinked. To implement the new SRTT and IDMSCTAB, either recycle any CVs that use the SRTT or issue these commands:

   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
    DCMT VARY NUCLEUS MODULE IDMSCTAB NEW COPY 
    DCMT VARY NUCLEUS RELOAD

Also verify the ESM gives access to the appropriate users. Here are Top Secret commands based on the above information. Assume that the SYSTEM ID in SYSGEN is TEST001:
TSS PER(user_id) CA@IDMS(TEST001.DCMT001)"
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55072r807776_chk'
  tag severity: 'medium'
  tag gid: 'V-251637'
  tag rid: 'SV-251637r855275_rule'
  tag stig_id: 'IDMS-DB-000660'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag fix_id: 'F-55026r807777_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
