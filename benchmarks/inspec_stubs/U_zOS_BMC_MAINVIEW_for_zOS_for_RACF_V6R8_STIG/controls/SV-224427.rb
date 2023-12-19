control 'SV-224427' do
  title 'BMC Mainview for z/OS Started task(s) must be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZMVZ0032)

Verify that the BMC Mainview for z/OS started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry.'
  desc 'fix', "The BMC Mainview system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique userid must be assigned for the BMC Mainview started task(s) thru a corresponding STARTED class entry.

The following sample set of commands is shown here as a guideline:

rdef started MV$CAS.** uacc(none) owner(admin) audit(all(read)) stdata(user(MV$CAS) group(stc))
rdef started MV$MVS.** uacc(none) owner(admin) audit(all(read)) stdata(user(MV$MVS) group(stc))

setr racl(started) ref"
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for RACF'
  tag check_id: 'C-26104r518989_chk'
  tag severity: 'medium'
  tag gid: 'V-224427'
  tag rid: 'SV-224427r518991_rule'
  tag stig_id: 'ZMVZR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26092r518990_fix'
  tag 'documentable'
  tag legacy: ['V-17454', 'SV-33841']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
