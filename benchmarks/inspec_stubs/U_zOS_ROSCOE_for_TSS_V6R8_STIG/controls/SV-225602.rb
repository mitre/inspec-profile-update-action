control 'SV-225602' do
  title 'ROSCOE Started task(s) must be properly defined to the Started Task Table ACID for Top Secret.'
  desc 'Access to product  resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)

Automated Analysis
Refer to the following report produced by the TSS Data Collection:

-	PDI(ZROS0032)

Verify that the ROSCOE started task(s) is (are) defined in the TSS STC record.'
  desc 'fix', "The ROSCOE system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique ACID must be assigned for the ROSCOE started task(s) thru a corresponding STC table entry.

The following sample set of commands is shown here as a guideline:

TSS ADD(STC) PROCNAME(ROSCOE) ACID(ROSCOE)"
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for TSS'
  tag check_id: 'C-27302r520865_chk'
  tag severity: 'medium'
  tag gid: 'V-225602'
  tag rid: 'SV-225602r520867_rule'
  tag stig_id: 'ZROST032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27290r520866_fix'
  tag 'documentable'
  tag legacy: ['V-17454', 'SV-24813']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
