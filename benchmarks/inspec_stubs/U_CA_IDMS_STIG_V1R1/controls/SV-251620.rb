control 'SV-251620' do
  title 'CA IDMS must permit the use of dynamic code execution only in circumstances determined by the organization and limit use of online and batch command facilities from which dynamic statements can be issued.'
  desc 'The IDMS Common Facilities (BCF and OCF) can execute commands that can make updates to IDMS, and their use should be protected.'
  desc 'check', 'Check the SRTT for externally secured resource TASK for command facility task codes (e.g., OCF or organization-defined task codes that invokes program IDMSOCF or IDMSBCF).

Examine load module RHDCSRTT by executing CA IDMS utility "IDMSSRTD", or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476.

Review the output looking for those statements that secure RESTYPE=TASK and RESNAMEs OCF or any organization-defined task codes that invoke programs IDMSOCF or IDMSBCF. If none are found for OCF, this is a finding.

BCF may not be defined as a task. If it is, this is a finding. 

The program invoked by installation-defined task codes can be determined by issuing command "DCMT DISP TASK" task-name.

Issue command "DCMT DISP TASK" and look for organization-defined tasks, then issue the "DCMT DISP TASK" task-name to determine the program being invoked. Review the code to determine if any of these execute dynamic code. If any do, this is a finding. 
                                                                                                                                                                                                                                   
If command facility tasks are found to be secured externally, ensure the external security manager (ESM) contains the correct definition using the external resource class name and the external resource name construction rules in the #SECRTT. If it is not defined or not defined correctly, this is a finding.'
  desc 'fix', "Create, or modify as needed, entries in the SRTT and then reassemble and relink the module RHDCSRTT for the security domain. An example of the external class and external name construction rules to secure OCF is:

#SECRTT TYPE=ENTRY,RESTYPE=TASK,SECBY=OFF,                                    X
  EXTNAME=(RESTYPE,RESNAME),EXTCLS='CA@IDMS'
#SECRTT TYPE=OCCUR,RESTYPE=TASK,RESNAME='OCF', SECBY=EXT

Consult with the security department to ensure that the ESM contains the correct rules to secure the entries and permit access to the appropriate users.

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:
 
   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
   DCMT VARY NUCLEUS RELOAD"
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55055r807725_chk'
  tag severity: 'medium'
  tag gid: 'V-251620'
  tag rid: 'SV-251620r807727_rule'
  tag stig_id: 'IDMS-DB-000490'
  tag gtitle: 'SRG-APP-000251-DB-000391'
  tag fix_id: 'F-55009r807726_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
