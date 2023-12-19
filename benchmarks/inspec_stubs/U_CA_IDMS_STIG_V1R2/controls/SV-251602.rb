control 'SV-251602' do
  title 'The programs that can be run through a CA IDMS CV must be defined to the CV to prevent installation of unauthorized programs; must have the ability to dynamically register new programs; and must have the ability to secure tasks.'
  desc 'The IDMS SYSGEN must be protected against unauthorized changes.

'
  desc 'check', %q(Check the SRTT for the externally secured resource SYST which allows the SYSGEN to be modified and application program definitions to be added. Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV and reviewing the output. 

Note: This requires PTFs SO07995 and SO09476.

If "SYST" is not found as the resource type in any of the entries, this is a finding. IF "SYST' is not coded with SECBY=EXTERNAL, this is a finding.

If "SYST" is found to be secured externally, ensure the external security manager (ESM) contains the correct definition using the external resource class name and the external name construction rules. If it is not defined or not defined correctly, this is a finding.

If the ESM definition is correct but the role(s)/groups(s) are not defined correctly to give the appropriate permissions, this is a finding.)
  desc 'fix', %q(The SRTT module must be coded to secure the system. When using an ESM, this could be done in the following manner:
 
#SECRTT TYPE=ENTRY,                          X
 RESTYPE=TASK,                                     X
 SECBY=EXTERNAL ,                               X
 EXTNAME=(RESTYPE,RESNAME),        X
  EXTCLS='CA@IDMS'

#SECRTT TYPE=OCCUR,                        X
  RESTYPE=TASK,                                   X
  RESNAME='SYSGEN',                          X
   SECBY=EXT

In the EXTNAME above, RESTYPE is changed to "TASK" and RESNAME is changed to "SYSGEN". 

Ensure the ESM has a corresponding entry to give access to the desired users. For instance, given a system named SYSO187, in Top Secret:
)  
TSS PER(user_id) CA@IDMS(TASK.SYSGEN)

In ACF2:
$KEY(TASK.SYSGEN) TYPE(CA@IDMS) 
 UID(user_id) ALLOW

RDEFINE CA@IDMS SYST UACC(NONE)
PERMIT TASK.SYSGEN CLASS(CA@IDMS) ID(user_id) ACCESS(READ)

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either cycle any CVs that use the SRTT or issue these commands:       
 
   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
   DCMT VARY NUCLEUS RELOAD)
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55037r807671_chk'
  tag severity: 'medium'
  tag gid: 'V-251602'
  tag rid: 'SV-251602r855261_rule'
  tag stig_id: 'IDMS-DB-000220'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-54991r807672_fix'
  tag satisfies: ['SRG-APP-000133-DB-000362', 'SRG-APP-000378-DB-000365']
  tag 'documentable'
  tag cci: ['CCI-001499', 'CCI-001812']
  tag nist: ['CM-5 (6)', 'CM-11 (2)']
end
