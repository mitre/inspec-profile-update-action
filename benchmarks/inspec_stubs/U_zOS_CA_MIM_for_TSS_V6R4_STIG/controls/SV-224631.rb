control 'SV-224631' do
  title 'CA MIM Resource Sharing Started task will be properly defined to the Started Task Table for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZMIM0032)

If the CA MIM Resource Sharing started task(s) is (are) defined in the TSS STC record, this is not a finding.'
  desc 'fix', 'The IAO working with the systems programmer will ensure the CA MIM Resource Sharing Started Task(s) is properly identified and/or defined to the System ACP. 

A unique ACID must be assigned for the CA MIM Resource Sharing started task(s) thru a corresponding STC table entry.

The following commands are provided as a sample for defining Started Task(s):

TSS ADD(STC) PROCNAME(MIMGR) ACID(MIMGR)'
  impact 0.5
  ref 'DPMS Target zOS CA MIM for TSS'
  tag check_id: 'C-26314r519662_chk'
  tag severity: 'medium'
  tag gid: 'V-224631'
  tag rid: 'SV-224631r519664_rule'
  tag stig_id: 'ZMIMT032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26302r519663_fix'
  tag 'documentable'
  tag legacy: ['V-17454', 'SV-46214']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
