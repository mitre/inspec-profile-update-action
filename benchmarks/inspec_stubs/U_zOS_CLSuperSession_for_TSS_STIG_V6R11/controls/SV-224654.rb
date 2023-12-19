control 'SV-224654' do
  title 'CL/SuperSession Started task(s) must be properly defined to the Started Task Table ACID for Top Secret.'
  desc 'Access to product  resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZCLS0032)

Verify that the CL/SuperSession started task(s) is (are) defined in the TSS STC record.'
  desc 'fix', "The CL/SuperSession system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique ACID must be assigned for the CL/SuperSession started task(s) thru a corresponding STC table entry.

The following sample set of commands is shown here as a guideline:

TSS ADD(STC) PROCNAME(KLS) ACID(KLS)"
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for TSS'
  tag check_id: 'C-26337r519779_chk'
  tag severity: 'medium'
  tag gid: 'V-224654'
  tag rid: 'SV-224654r519781_rule'
  tag stig_id: 'ZCLST032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26325r519780_fix'
  tag 'documentable'
  tag legacy: ['V-17454', 'SV-27238']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
