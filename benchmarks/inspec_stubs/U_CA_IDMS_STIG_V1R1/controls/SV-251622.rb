control 'SV-251622' do
  title 'CA IDMS must limit  use of IDMS server used in issuing dynamic statements from client applications circumstances determined by the organization.'
  desc 'Server tasks can execute dynamic SQL code and should be protected.'
  desc 'check', 'Check the SRTT for externally secured resource TASK for IDMS Server task codes IDMSJSRV and CASERVER.

Examine load module RHDCSRTT by executing CA IDMS utility "IDMSSRTD", or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476.

If no TASK entry is found for either IDJSJSRV or CASERVER, this is a finding. 

If either is not secured external, this is a finding.

If tasks IDMSJSRV and CASERVER are found to be secured externally, ensure that the external security manager (ESM) contains the correct definition using the external resource class name and the external name construction rules. If it is not defined or not defined correctly, this is a finding.'
  desc 'fix', "Create or modify as needed entries in the SRTT, then reassemble and relink module RHDCSRTT for the security domain. The external class and external name construction rules must be specified. The following is an example of how IDMSJSRV and CASERVER may be secured externally.

#SECRTT TYPE=ENTRY,RESTYPE=TASK,SECBY=OFF,EXTNAME=(RESTYPE,RESNAME),
  EXTCLS='CA@IDMS'
#SECRTT TYPE=OCCUR,RESTYPE=TASK,RESNAME='IDMSJSRV', SECBY=EXT
#SECRTT TYPE=OCCUR,RESTYPE=TASK,RESNAME='CASERVER', SECBY=EXT

Consult with the security department to ensure that the ESM contains the correct rules to secure the entries and permit access to the appropriate users.

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:
 
   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
   DCMT VARY NUCLEUS RELOAD"
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55057r807731_chk'
  tag severity: 'medium'
  tag gid: 'V-251622'
  tag rid: 'SV-251622r807733_rule'
  tag stig_id: 'IDMS-DB-000510'
  tag gtitle: 'SRG-APP-000251-DB-000391'
  tag fix_id: 'F-55011r807732_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
