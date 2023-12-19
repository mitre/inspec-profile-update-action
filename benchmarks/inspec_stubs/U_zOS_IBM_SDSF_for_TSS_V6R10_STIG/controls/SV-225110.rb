control 'SV-225110' do
  title 'IBM System Display and Search Facility (SDSF) Started task will be properly defined to the Started Task Table ACID for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources. Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZISF0032)

If the IBM SDSF started task(s) is (are) defined in the TSS STC record, this is not a finding.'
  desc 'fix', 'The ISSO working with the systems programmer will ensure the IBM SDSF Started Task(s) is properly identified and/or defined to the System ACP.

A unique ACID must be assigned for the IBM SDSF started task(s) thru a corresponding STC table entry.

The following commands are provided as a sample for defining Started Task(s):

TSS ADD(STC) PROCNAME(SDSF) ACID(SDSF)'
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for TSS'
  tag check_id: 'C-26809r840210_chk'
  tag severity: 'medium'
  tag gid: 'V-225110'
  tag rid: 'SV-225110r840212_rule'
  tag stig_id: 'ZISFT032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26797r840211_fix'
  tag 'documentable'
  tag legacy: ['V-17454', 'SV-40825']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
