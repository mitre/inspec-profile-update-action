control 'SV-224665' do
  title 'Compuware Abend-AID Started task will be properly defined to the Started Task Table for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZAID0032)

If the Compuware Abend-AID started task(s) is (are) defined in the TSS STC record, this is not a finding.'
  desc 'fix', 'The IAO working with the systems programmer will ensure the Compuware Abend-AID Started Task(s) is properly identified and/or defined to the System ACP. 

A unique ACID must be assigned for the Compuware Abend-AID started task(s) thru a corresponding STC table entry.

The following commands are provided as a sample for defining Started Task(s):

TSS ADD(STC) PROCNAME(AAVIEWER) ACID(AAVIEWER)
TSS ADD(STC) PROCNAME(BDCAS) ACID(BDCAS)
TSS ADD(STC) PROCNAME(TDCAS) ACID(TDCAS)'
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for TSS'
  tag check_id: 'C-26348r519851_chk'
  tag severity: 'medium'
  tag gid: 'V-224665'
  tag rid: 'SV-224665r519853_rule'
  tag stig_id: 'ZAIDT032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26336r519852_fix'
  tag 'documentable'
  tag legacy: ['SV-43186', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
