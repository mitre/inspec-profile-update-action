control 'SV-251606' do
  title 'The online debugger which can change programs and storage in the CA IDMS address space must be secured.'
  desc 'If the DBMS were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.

Users of the online debugger may alter programs and storage in the IDMS CV.

'
  desc 'check', %q(Examine the load module RHDCSRTT by executing CA IDMS utility "IDMSSRTD", or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV and reviewing the output. 

Note: This requires PTFs SO07995 and SO09476. 

Check the SRTT for externally secured ACTI where the task name is DBUG. If none is found, this is a finding. 

If the entry is secured internally, this is a finding. 

If an ACTI statement for DBUG that secures DBUG externally is found, verify the program IDMSGTAB resides in the CV's CMDSLIB concatenation. If not, this is a finding. 

If IDMSGTAB is found, perform a DUMPT of IDMSGTAB using AMASPZAP. The last 28 bytes are a table of 14 halfwords, one for each security category that can be secured by the #GTABGEN macro. Examine this table in the DUMPT. If all halfwords are zero, and no debugger functions are secure, and this is a finding. 

If any halfword is non-zero, then the first byte will be x'01' and the second byte will contain the activity number assigned to that function in hexadecimal. The order of the security-categories in the table is:
UPGMR
UPGMU
USTGR
USTGU
SHSTGR
SHSTGU
AUPGMR
AUPGMU
ASYSTGR
ASYSTGU
ASYSPGR
ASYSPGU
ALLR
ALLU

If the debug activity is found to be secured externally, confer with the security office to ensure that the external security manager (ESM) contains the correct definition using the external resource class name the external name construction rules. If it is not defined correctly, this is a finding. 

If the ESM definition is correct but the role(s)/groups(s) are not defined correctly to give the appropriate permissions, this is a finding.)
  desc 'fix', "Create, or modify as needed, an entry in the SRTT to secure the DEBUG categories and compile into module RHDCSRTT. The external class and external name construction rules must be specified. 

The following example shows a TYPE=ENTRY #SECRTT macro defining the EXTNAME format for RESTYPE=ACTI and an occurrence override defining the information for a specific occurrence for the DBUG activity. 

#SECRTT TYPE=ENTRY,RESTYPE=ACTI,SECBY=OFF,
 EXTNAME=(ENVIR,ACTI) ,EXTCLS='CA@IDMS' 
#SECRTT TYPE=OCCUR,RESTYPE=ACTI,RESNAME='DBUG',SECBY=EXT

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:

   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
   DCMT VARY NUCLEUS RELOAD

Review the IDMSGTAB module and make changes to the #GTABGEN macro as needed. Here is an example that secures all possible DEBUG categories:  
 
         #GTABGEN (A,01,B,02,C,03,D,04,E,05,F,06,G,07,H,08,I,09,J,10,  X
               K,11,L,12,M,13,N,14),                                   X
               (UPGMR,A,UPGMU,B,USTGR,C,USTGU,D,SHSTGR,E,SHSTGU,F,     X
               AUPGMR,G,AUPGMU,H,ASYSTGR,I,ASYSTGU,J,                  X
               ASYSPGR,K,ASYSPGU,L,ALLR,M,ALLU,N)                       
         END                                                            

Assume the TYPE=INITIAL #SECRTT macro specified ENVNAME=TEST0001 and the particular debug activity was UPGMR (allow the user to retrieve user programs, schemas, maps, and tables). In that case, the external resource name would be TEST0001.DBUG001. Using this information, a Top Secret example to grant access could be:
TSS PER(user_1) CA@IDMS(TEST0001.DBUG001) 

Confer with the security office to ensure that the correct entries are in the ESM to give access to the appropriate role(s)/group(s) permissions for the desired DEBUG categories."
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55041r807683_chk'
  tag severity: 'medium'
  tag gid: 'V-251606'
  tag rid: 'SV-251606r807685_rule'
  tag stig_id: 'IDMS-DB-000260'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-54995r807684_fix'
  tag satisfies: ['SRG-APP-000133-DB-000362', 'SRG-APP-000380-DB-000360']
  tag 'documentable'
  tag cci: ['CCI-001499', 'CCI-001813']
  tag nist: ['CM-5 (6)', 'CM-5 (1) (a)']
end
