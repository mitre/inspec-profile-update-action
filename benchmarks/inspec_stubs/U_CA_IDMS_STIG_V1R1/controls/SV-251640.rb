control 'SV-251640' do
  title 'CA IDMS programs that can be run through a CA IDMS CV must be defined to the CV.'
  desc 'The ability to add programs to be executed under IDMS can be a problem if malicious programs are added. CA IDMS must prevent installation of unauthorized programs and the ability to dynamically register new programs and tasks.'
  desc 'check', 'Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476.

Check the SRTT for externally secured resource SYST which allows the SYSGEN to be modified and application program definitions added. If "SYST" is not found as the resource type in any of the entries, this is a finding. 

If "SYST" is secured internally, this is a finding.                                                                                                                                                                                                                                                   

If "SYST" is found to be secured externally, ensure that the ESM contains the correct definition using the external resource class name and the external name construction rules. If it is not defined or not defined correctly, this is a finding.'
  desc 'fix', "Create an entry in the SRTT and compile into the module RHDCSRTT for the security domain that defined the resource type of SYST. The external class and external name construction rules must be specified. For instance:
 
#SECRTT TYPE=ENTRY,RESTYPE=SYST, SECBY=EXTERNAL, EXTCLS='CA@IDMS',EXTNAME=(RESNAME)

Create the corresponding entry in the external security manager (ESM) and authorize appropriate users, groups, etc., to allow access to system generation including program definition."
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55075r807785_chk'
  tag severity: 'medium'
  tag gid: 'V-251640'
  tag rid: 'SV-251640r807787_rule'
  tag stig_id: 'IDMS-DB-000720'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-55029r807786_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
