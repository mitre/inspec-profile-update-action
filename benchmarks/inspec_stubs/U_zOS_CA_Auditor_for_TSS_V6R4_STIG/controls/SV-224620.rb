control 'SV-224620' do
  title 'CA Auditor resources are not properly defined and protected.'
  desc 'CA Auditor can run with sensitive system privileges, and potentially can circumvent system controls.  Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data.  Many utilities assign resource controls that can be granted to system programmers only in greater than read authority.  Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following reports produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(ZADT0020)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZADT0020)

Verify that the access to the LTDMMAIN resource in the PROGRAM resource class is restricted.

___	The TSS owner is defined for the prefix of the resource and/or the resource classes RDT entry has DEFPROT specified.

___	The TSS rules for the resources are restricted access to system programmers, auditors, and security personnel.'
  desc 'fix', 'The IOA will verify that the LTDMMAIN resource in the PROGRAM resource class is restricted to system programmers, auditors, and security personnel.

The TSS owner is defined for the LTDMMAIN resource and/or PROGRAM RDT entry has DEFPROT specified.

Example:

TSS ADD(dept-acid)PROGRAM(LTDMMAIN)

TSS REP(RDT)RESCLASS(PROGRAM)ATTR(DEFPROT)

The TSS rules for the LTDMMAIN resource is restricted access to system programmers, auditors, and security personnel.

Example:

TSS PERMIT(audtaudt)PROGRAM(LTDMMAIN)
TSS PERMIT(secaaudt)PROGRAM(LTDMMAIN)
TSS PERMIT(syspaudt)PROGRAM(LTDMMAIN)'
  impact 0.5
  ref 'DPMS Target zOS CA Auditor for TSS'
  tag check_id: 'C-26303r519569_chk'
  tag severity: 'medium'
  tag gid: 'V-224620'
  tag rid: 'SV-224620r855117_rule'
  tag stig_id: 'ZADTT020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26291r519570_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-32210']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
