control 'SV-225611' do
  title 'IBM Tivoli Asset Discovery for zOS (TADz) Started task(s) must be properly defined to the Started Task Table ACID for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZTAD0032)

Verify that the IBM Tivoli Asset Discovery for zOS (TADz) started task(s) is (are) defined in the TSS STC record.'
  desc 'fix', "The IBM Tivoli Asset Discovery for zOS (TADz) system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP.  

A unique ACID must be assigned for the IBM Tivoli Asset Discovery for zOS (TADz) started task(s) thru a corresponding STC table entry.

The following sample set of commands is shown here as a guideline:

TSS ADD(STC) PROCNAME(TADZMON) ACID(TADZMON)"
  impact 0.5
  ref 'DPMS Target zOS TADz for TSS'
  tag check_id: 'C-27311r472632_chk'
  tag severity: 'medium'
  tag gid: 'V-225611'
  tag rid: 'SV-225611r472634_rule'
  tag stig_id: 'ZTADT032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27299r472633_fix'
  tag 'documentable'
  tag legacy: ['SV-28562', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
