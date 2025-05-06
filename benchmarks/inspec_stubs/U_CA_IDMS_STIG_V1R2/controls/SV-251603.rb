control 'SV-251603' do
  title 'The commands that allow dynamic definitions of PROGRAM/TASK and the dynamic varying of memory must be secured.'
  desc 'IDMS provides commands that can change memory, the attributes of programs, or tasks and are meant for use by the appropriate administrators. These commands must be protected from use by the wrong personnel.

'
  desc 'check', 'Check the SRTT for externally secured ACTI resource which can be used to secure DCMT VARY DYNAMIC PROGRAM, DCMT VARY DYNAMIC TASK and DCMT VARY MEMORY.

Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476.

If "ACTI" is not found as the resource type in any of the entries, this is a finding.

IF "ACTI" is found but has SECBY=INTERNAL, this is a finding. 

If no entry is securing VARY DYNAMIC and VARY MEMORY externally, this is a finding. 

If there is no IDMSCTAB load module into which the #CTABGEN has been generated that specifies the nodes names that correspond to the DCMT commands (DCMT VARY DYNAMIC - N046; DCMT VARY MEMORY - N033), this is a finding.                                                                                                                                                                                                                               

Examine load module IDMSCTAB using CA IDMS utility IDMSCTAD, or by issuing command "DCMT DISPLAY CTAB" while signed onto the CV, and reviewing the output. Note that this requires PTF SO08199. If DCMT command codes N024, N025, and N033 are not defined, this is a finding.'
  desc 'fix', "The SRTT must contain one or more entries to enable the external security of RESTYPE=ACTI. For example:
 
#SECRTT TYPE=ENTRY,RESTYPE=ACTI, SECBY=EXTERNAL,      EXTCLS='CA@IDMS',EXTNAME=(SYST,ACTIVITY)       

Update the source for IDMSCTAB. This example #CTABGEN entry secures the DCMT VARY DYNAMIC and DCMT VARY MEMORY commands and assigns an activity number to each:

CTAB  TITLE 'GENERATE DCMT SECURITY TABLE'                              
         #CTABGEN LOGIN=YES,                                                      X
               (A,1,B,10),                                                                     X
               (N033,A,N046,B)                          
         END                                                            

The ACTIVITY passed to the external security manager (ESM) will be the first up to five bytes of the application name followed by the three-byte activity number or, using the above example, DCMT010 for a DCMT VARY DYNAMIC or a DMCT VARY MEMORY command. 
 
After making the above changes, IDMSCTAB and RHDCSRTT must then be reassembled and relinked. To implement the new SRTT and IDMSCTAB, either recycle any CVs that use the SRTT or issue these commands:

   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
    DCMT VARY NUCLEUS MODULE IDMSCTAB NEW COPY 
    DCMT VARY NUCLEUS RELOAD

Also verify that the ESM gives access to the appropriate people. Here are some Top Secret commands based on the above information. Assume that the SYSTEM ID in SYSGEN is TEST001:

TSS PER(user_id) CA@IDMS(TEST001.DCMT001) ACCESS(READ)
TSS PER(user_id) CA@IDMS(TEST001.DCMT010) ACCESS(READ)"
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55038r807674_chk'
  tag severity: 'medium'
  tag gid: 'V-251603'
  tag rid: 'SV-251603r855262_rule'
  tag stig_id: 'IDMS-DB-000230'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-54992r807675_fix'
  tag satisfies: ['SRG-APP-000133-DB-000362', 'SRG-APP-000380-DB-000360', 'SRG-APP-000378-DB-000365']
  tag 'documentable'
  tag cci: ['CCI-001499', 'CCI-001812', 'CCI-001813']
  tag nist: ['CM-5 (6)', 'CM-11 (2)', 'CM-5 (1) (a)']
end
