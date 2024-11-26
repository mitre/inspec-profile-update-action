control 'SV-224668' do
  title 'IBM CSSMTP Started task(s) must be properly defined to the Started Task Table ACID for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZSMT0032)

Verify that the IBM CSSMTP started task(s) is (are) defined in the TSS STC record.'
  desc 'fix', "The IBM CSSMTP system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique ACID must be assigned for the IBM CSSMTP started task(s) thru a corresponding STC table entry.

The following sample set of commands is shown here as a guideline:

TSS ADD(STC) PROCNAME(CSSMTP) ACID(CSSMTP)"
  impact 0.5
  ref 'DPMS Target zOS CSSMTP for TSS'
  tag check_id: 'C-26357r519875_chk'
  tag severity: 'medium'
  tag gid: 'V-224668'
  tag rid: 'SV-224668r519877_rule'
  tag stig_id: 'ZSMTT032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26345r519876_fix'
  tag 'documentable'
  tag legacy: ['SV-37484', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
