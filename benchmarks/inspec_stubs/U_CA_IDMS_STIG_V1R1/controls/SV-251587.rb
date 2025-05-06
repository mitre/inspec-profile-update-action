control 'SV-251587' do
  title 'All installation-delivered IDMS DEVELOPER-level tasks must be properly secured.'
  desc 'Developer-level tasks that are not secured may allow anyone who signs on to IDMS to use them to access and manipulate various resources within the DBMS.

'
  desc 'check', 'Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV and reviewing the output. 

Note: This requires PTFs SO07995 and SO09476.

Validate the following suggested developer-level tasks are secured in the SRTT (included, for example, in the roles of DCADMIN, DBADMIN level security).

Note: USER, DEVELOPER, DBADMIN, and DCADMIN are suggested categories only.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
ADSA
ADSAT
ADSC 
ADSCT
ADSK  
ADSL    
DEBUG   
IDDML
IDDM   
IDDT    
LOOK    
MAPB    
MAPBT   
MAPC    
MAPCT   
PMAM    
PMIM    
QUED    
SCHEMA  
SCHEMAT 
SHOWMAP 

If "TASK" is not found as the resource type in any of the entries, this is a finding. 

If "TASK" is secured internally, this is a finding. 

If "TASK" is secured externally in the SRTT, review the SRTT entries to ensure that the above tasks are secured and review ESM for external class and external name format to make sure the appropriate authorizations have been defined. If they have not, this is a finding.'
  desc 'fix', %q(The SRTT module must be coded to enable task-level security. When using an external security manager (ESM), this could be done in the following manner:
 
#SECRTT TYPE=ENTRY,                         X
 RESTYPE=TASK,                                    X
 SECBY=EXTERNAL ,                               X
 EXTNAME=(RESTYPE,RESNAME),        X
 EXTCLS='CA@IDMS'

or to give access specifically to one or more tasks (in this case, to ADSA):

#SECRTT TYPE=ENTRY, RESTYPE=TASK,                             X
  SECBY=OFF,                                                                        X               
  EXTNAME=(RESTYPE,RESNAME),EXTCLS='CA@IDMS'

with an OCCUR statement for each task:

#SECRTT TYPE=OCCUR,RESTYPE=TASK,                               X
 SECBY=EXTERNAL,                                                                 X 
 RESNAME='ADSA'                                                                           

Using the above examples, the ESM must be configured to grant access for resource name "TASK.task-name" to security group (or role) DEVELOPER, for security class "CA@IDMS", where "task-name" is one of the developer-level tasks listed. 

This grant must be repeated for each Task in the list. These rules should then be given to the appropriate users. For instance, in Top Secret:
TSS PER(user_id) CA@IDMS(TASK.ADSA)  

In ACF2:
$KEY(TASK.ADSA) TYPE(CA@IDMS) 
 UID(user_id) ALLOW

In RACF:
PERMIT TASK.ADSA CLASS(CA@IDMS) ID(user_id) ACCESS(READ)

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:       
 
DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
DCMT VARY NUCLEUS RELOAD)
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55022r808350_chk'
  tag severity: 'medium'
  tag gid: 'V-251587'
  tag rid: 'SV-251587r808352_rule'
  tag stig_id: 'IDMS-DB-000070'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-54976r808351_fix'
  tag satisfies: ['SRG-APP-000033-DB-000084', 'SRG-APP-000211-DB-000122']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-001082']
  tag nist: ['AC-3', 'SC-2']
end
