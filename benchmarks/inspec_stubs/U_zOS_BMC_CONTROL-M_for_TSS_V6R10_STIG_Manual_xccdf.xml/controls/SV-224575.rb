control 'SV-224575' do
  title 'BMC CONTROL-M Started task(s) must be properly defined to the Started Task Table ACID for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZCTM0032)

Verify that the BMC CONTROL-M started task(s) is (are) defined in the TSS STC record.'
  desc 'fix', "The BMC CONTROL-M system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique ACID must be assigned for the BMC CONTROL-M started task(s) thru a corresponding STC table entry.

The following sample set of commands is shown here as a guideline:

TSS ADD(STC) PROCNAME(CONTOLM) ACID(CONTROLM)"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for TSS'
  tag check_id: 'C-26258r518788_chk'
  tag severity: 'medium'
  tag gid: 'V-224575'
  tag rid: 'SV-224575r518790_rule'
  tag stig_id: 'ZCTMT032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26246r518789_fix'
  tag 'documentable'
  tag legacy: ['SV-32158', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
