control 'SV-251605' do
  title 'Database utilities must be secured in CA IDMS and permissions given to appropriate role(s)/groups(s) in the external security manager (ESM).'
  desc 'IDMS has tasks that are used to perform necessary maintenance, but in the wrong hands could damage the integrity of the DBMS. Tasks that can change database structure must be protected.

'
  desc 'check', 'Check the SRTT for externally secured ACTI which can be used to secure utility functions that can impact database structure, e.g., CONVERTCATALOG, CONVERTPAGE, EXPANDPAGE, MAINTAININDEX, REORG, RESTRUCTURE and TUNEINDEX. For a full list, see the UTABGEN UTILITY COMMAND CODES table in the Administrating Security for IDMS manual.

Examine load module IDMSUTAB using CA IDMS utility IDMSUTAD, or by issuing command "DCMT DISPLAY UTAB" while signed onto the CV, and reviewing the output.

Note: This requires PTF SO08527.  

If there is no IDMSUTAB load module into which the #UTABGEN has been generated that specifies the nodes names that correspond to the UTILITY statements, this is a finding.

Examine load module RHDCSRTT by executing CA IDMS utility "IDMSSRTD", or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV and reviewing the output. 

If "ACTI" is not found as the resource type in any of the entries, this is a finding. IF "ACTI" is found to be secured internally, this is a finding.                                                                                                                                                                                                                                        

If "ACTI" is found to be secured externally, ensure that the ESM contains the correct definition using the external resource class name and the external name construction rules. If it is not defined or not defined correctly, this is a finding. 

If the ESM definition is correct but the role(s)/groups(s) are not defined correctly to give the appropriate permissions, this is a finding.
 
Note: There are alternative ways to secure utilities by using RESTYPE=DB and corresponding ESM definitions can give authorization to appropriate role(s)/group(s).'
  desc 'fix', %q(Create an entry in the SRTT and compile into the module RHDCSRTT for the security domain that defined the resource type of ACTI. The external class and external name construction rules must be specified. For example:

#SECRTT TYPE=ENTRY,RESTYPE=ACTI, SECBY=EXTERNAL, EXTCLS='CA@IDMS',EXTNAME=(RESNAME,ACTIVITY)                                                                                                                                                                                                                                                                                                                                                      

Compile IDMSUTAB into the custom loadlib, specifying the activity number associated with the utility statement on the #UTABGEN macro. For example, #UTABGEN (A,3),(OCF,EXPANDPAGE,I). The ACTIVITY passed to the ESM will be the first up to five bytes of the application name followed by the three-byte activity number. Using the activity number "3" in the #UTABGEN, the ACTIVITY sent to the ESM would be OCF003.

Create the corresponding entry in the ESM and give appropriate permissions to roles(s)/group(s) for the ACTIVITY (e.g., OCF003 which would secure the EXPANDPAGE utility statement).)
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55040r807680_chk'
  tag severity: 'medium'
  tag gid: 'V-251605'
  tag rid: 'SV-251605r855264_rule'
  tag stig_id: 'IDMS-DB-000250'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-54994r807681_fix'
  tag satisfies: ['SRG-APP-000133-DB-000362', 'SRG-APP-000380-DB-000360']
  tag 'documentable'
  tag cci: ['CCI-001499', 'CCI-001813']
  tag nist: ['CM-5 (6)', 'CM-5 (1) (a)']
end
