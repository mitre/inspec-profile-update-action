control 'SV-251589' do
  title 'All installation-delivered IDMS DCADMIN-level tasks must be properly secured.'
  desc 'If DC Administrator-level tasks are not secured, any user logged on to IDMS may use them to access and manipulate various resources within the DBMS. This can be mitigated using the proper entries in the SRTT.

'
  desc 'check', 'Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output. 

Note: This requires PTFs SO07995 and SO09476. 

Validate the following suggested DC-Administrator-level tasks are secured in the SRTT. If they are not secured, this is a finding. (Note that USER, DEVELOPER, DBADMIN, and DCADMIN are suggested categories only).
 ASF    
 CLOD    
 DCMT    
 OPER    
 PMBILL  
 PMRM    
 SDEL    
 SEND    
 SYSGEN  
 SYSGENT 
 WEBC            
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
 If "TASK" is not found as the resource type in any of the entries, this is a finding. 

IF "TASK" is secured internally, this is a finding. 

If "TASK" is secured externally in the SRTT, review the SRTT entries to ensure that the above tasks are secured, and review the external security manager (ESM) for external class and external name format to make sure the appropriate authorizations have been defined. If they have not, this is a finding.'
  desc 'fix', %q(The SRTT module must be coded to enable task-level security. When using an ESM, this could be done in the following manner:
 
#SECRTT TYPE=ENTRY,                          X
 RESTYPE=TASK,                                     X
 SECBY=EXTERNAL ,                               X
 EXTNAME=(RESTYPE,RESNAME),        X
 EXTCLS='CA@IDMS'

or to give access specifically to one or more programs (in this case, to ASF):

#SECRTT TYPE=ENTRY, RESTYPE=TASK,                             X
  SECBY=OFF,                                                                        X               
 EXTNAME=(RESTYPE,RESNAME),EXTCLS='CA@IDMS'

with an OCCUR statement for each task:

#SECRTT TYPE=OCCUR,RESTYPE=TASK,                              X
 SECBY=EXTERNAL,                                                                X 
 RESNAME='ASF'                                                                           

Using the above examples, the ESM must be configured to grant access for resource name "TASK.task-name" to security group (or role) DCADMIN, for security class "CA@IDMS", where "task-name" is one of  the DC-Administrator-level programs listed. The appropriate ESM rules must then be given to the appropriate users. For instance, in Top Secret:
TSS PER(user_id) CA@IDMS(TASK.ASF) 

In ACF2:
$KEY(SGON.the_extname) TYPE(TASK.ASF) 
 UID(user_id) ALLOW

In RACF:
RDEFINE CA@IDMS TASK.TASK.ASF UACC(NONE)
PERMIT TASK.ASF CLASS(CA@IDMS) ID(user_id) ACCESS(READ)

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:       
 DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
DCMT VARY NUCLEUS RELOAD)
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55024r807632_chk'
  tag severity: 'medium'
  tag gid: 'V-251589'
  tag rid: 'SV-251589r807634_rule'
  tag stig_id: 'IDMS-DB-000090'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-54978r807633_fix'
  tag satisfies: ['SRG-APP-000033-DB-000084', 'SRG-APP-000211-DB-000122']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-001082']
  tag nist: ['AC-3', 'SC-2']
end
