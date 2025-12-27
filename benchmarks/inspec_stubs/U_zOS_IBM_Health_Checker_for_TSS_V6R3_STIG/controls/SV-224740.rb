control 'SV-224740' do
  title 'IBM Health Checker Started task will be properly defined to the Started Task Table for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZHCK0032)

If the IBM Health Checker started task(s) is (are) defined in the TSS STC record, this is not a finding.'
  desc 'fix', 'The IAO working with the systems programmer will ensure the IBM Health Checker Started Task(s) is properly identified and/or defined to the System ACP. 

A unique ACID must be assigned for the IBM Health Checker started task(s) thru a corresponding STC table entry.

The following commands are provided as a sample for defining Started Task(s):

TSS ADD(STC) PROCNAME(HZSPROC) ACID(HZSPROC)'
  impact 0.5
  ref 'DPMS Target zOS IBM Health Checker for TSS'
  tag check_id: 'C-26431r520337_chk'
  tag severity: 'medium'
  tag gid: 'V-224740'
  tag rid: 'SV-224740r520339_rule'
  tag stig_id: 'ZHCKT032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26419r520338_fix'
  tag 'documentable'
  tag legacy: ['SV-43188', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
