control 'SV-225579' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Started task(s) must be properly defined to the Started Task Table ACID for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZICS0032)

Verify that the IBM Integrated Crypto Service Facility (ICSF) started task(s) is (are) defined in the TSS STC record.'
  desc 'fix', "The IBM Integrated Crypto Service Facility (ICSF) system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique ACID must be assigned for the IBM Integrated Crypto Service Facility (ICSF) started task(s) thru a corresponding STC table entry.

The following sample set of commands is shown here as a guideline:

TSS ADD(STC) PROCNAME(CSFSTART) ACID(CSFSTART)"
  impact 0.5
  ref 'DPMS Target zOS ICSF for TSS'
  tag check_id: 'C-27278r472533_chk'
  tag severity: 'medium'
  tag gid: 'V-225579'
  tag rid: 'SV-225579r472535_rule'
  tag stig_id: 'ZICST032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27266r472534_fix'
  tag 'documentable'
  tag legacy: ['V-17454', 'SV-30580']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
