control 'SV-251648' do
  title 'The storage used for data collection by CA IDMS Server and CA IDMS Web Services must be protected from online display and update.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When transmitting data, the DBMS, associated applications, and infrastructure must leverage transmission protection mechanisms.

'
  desc 'check', 'Check the SRTT for externally secured ACTI which can be used to secure DCMT DISPLAY MEMORY and DCMT VARY MEMORY.

Examine load module RHDCSRTT using CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV and reviewing the output. 

Note: This requires PTFs SO07995 and SO09476.

If RESTYPE=ACTI is not found as the resource type in any of the entries, this is a finding. If RESTYPE=ACTI is found but the entry is secured internally, this is a finding.

Examine load module IDMSCTAB using CA IDMS utility IDMSCTAD, or by issuing command "DCMT DISPLAY CTAB" while signed onto the CV and reviewing the output. 

Note: This requires PTF SO08199. 

Verify that these DCMT command codes are present:
N022 - DISPLAY MEMORY
N033 - VARY MEMORY
If they are not present, this is a finding.'
  desc 'fix', "The SRTT must contain one or more entries to enable the external security of RESTYPE=ACTI. For example:
 
#SECRTT TYPE=ENTRY,RESTYPE=ACTI, SECBY=EXTERNAL,      EXTCLS='CA@IDMS',EXTNAME=(SYST,ACTIVITY)

Update the source for IDMSCTAB. This example #CTABGEN entry secures the DCMT DISPLAY MEMORY and DCMT VARY MEMORY commands and assigns an activity number to each:

CTAB  TITLE 'GENERATE DCMT SECURITY TABLE'                              
         #CTABGEN LOGIN=YES,                                                      X
               (A,1,B,11),                                                                       X
               (N033,A,                 VARY MEMORY   - TASK   1         X
               N022,B)                  DISPLAY MEMORY   -   TASK 11
         END                                                            

The ACTIVITY passed to the ESM will be the first up to 5 bytes of the application name followed by the 3 byte activity number or, using the above example, DCMT011 for a DCMT DISPLAY MEMORY. 
 
After making the above changes, IDMSCTAB and RHDCSRTT must be reassembled and relinked. To implement the new SRTT and IDMSCTAB, either recycle any CVs that use the SRTT or issue these commands:       
 
   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
    DCMT VARY NUCLEUS MODULE IDMSCTAB NEW COPY 
    DCMT VARY NUCLEUS RELOAD

Also, verify the ESM gives access to the appropriate people. Here are some Top Secret commands based on the above information. Assume that the SYSTEM ID in SYSGEN is TEST001:
TSS PER(user_id) CA@IDMS(TEST001.DCMT001) 
TSS PER(user_id) CA@IDMS(TEST001.DCMT011)"
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55083r807809_chk'
  tag severity: 'medium'
  tag gid: 'V-251648'
  tag rid: 'SV-251648r807811_rule'
  tag stig_id: 'IDMS-DB-000840'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-55037r807810_fix'
  tag satisfies: ['SRG-APP-000441-DB-000378', 'SRG-APP-000442-DB-000379']
  tag 'documentable'
  tag cci: ['CCI-002420', 'CCI-002422']
  tag nist: ['SC-8 (2)', 'SC-8 (2)']
end
