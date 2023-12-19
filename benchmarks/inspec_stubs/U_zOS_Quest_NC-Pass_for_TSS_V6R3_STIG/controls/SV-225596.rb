control 'SV-225596' do
  title 'Quest NC-Pass Started task will be properly defined to the Started Task Table ACID for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZNCP0032)

If the Quest NC-Pass started task(s) is (are) defined in the TSS STC record, this is not a finding.'
  desc 'fix', 'The IAO working with the systems programmer will ensure the Quest NC-Pass Started Task(s) is properly identified and/or defined to the System ACP.

A unique ACID must be assigned for the CA 1 Tape Management started task(s) thru a corresponding STC table entry.

The following commands are provided as a sample for defining Started Task(s):

TSS ADD(STC) PROCNAME(NCPASS) ACID(NCPASS)'
  impact 0.5
  ref 'DPMS Target zOS Quest NC-Pass for TSS'
  tag check_id: 'C-27296r472587_chk'
  tag severity: 'medium'
  tag gid: 'V-225596'
  tag rid: 'SV-225596r472589_rule'
  tag stig_id: 'ZNCPT032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27284r472588_fix'
  tag 'documentable'
  tag legacy: ['V-17454', 'SV-40876']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
