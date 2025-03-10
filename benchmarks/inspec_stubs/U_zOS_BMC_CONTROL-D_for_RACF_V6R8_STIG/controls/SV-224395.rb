control 'SV-224395' do
  title 'BMC CONTROL-D Started task(s) must be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZCTD0032)

Verify that the BMC CONTROL-D started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry.'
  desc 'fix', "The BMC CONTROL-D system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique userid must be assigned for the BMC CONTROL-D started task(s) thru a corresponding STARTED class entry.

The following sample set of commands is shown here as a guideline:

rdef started CONTROLD.** uacc(none) owner(admin) audit(all(read)) stdata(user(CONTROLD) group(stc))

setr racl(started) ref"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-D for RACF'
  tag check_id: 'C-26072r518686_chk'
  tag severity: 'medium'
  tag gid: 'V-224395'
  tag rid: 'SV-224395r518688_rule'
  tag stig_id: 'ZCTDR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26060r518687_fix'
  tag 'documentable'
  tag legacy: ['SV-32155', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
