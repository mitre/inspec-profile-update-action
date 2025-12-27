control 'SV-224611' do
  title 'BMC Mainview for z/OS Started task(s) must be properly defined to the Started Task Table ACID for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZMVZ0032)

Verify that the BMC Mainview for z/OS started task(s) is (are) defined in the TSS STC record.'
  desc 'fix', "The BMC Mainview for z/OS system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique ACID must be assigned for the BMC Mainview for z/OS started task(s) thru a corresponding STC table entry.

The following sample set of commands is shown here as a guideline:

TSS ADD(STC) PROCNAME(MV$CAS) ACID(MV$CAS)
TSS ADD(STC) PROCNAME(MV$MVS) ACID(MV$MVS)"
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for TSS'
  tag check_id: 'C-26294r519010_chk'
  tag severity: 'medium'
  tag gid: 'V-224611'
  tag rid: 'SV-224611r519012_rule'
  tag stig_id: 'ZMVZT032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26282r519011_fix'
  tag 'documentable'
  tag legacy: ['V-17454', 'SV-33842']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
