control 'SV-224421' do
  title 'BMC IOA Started task(s) must be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZIOA0032)

Verify that the BMC IOA started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry.'
  desc 'fix', "The BMC IOA system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique userid must be assigned for the BMC IOA started task(s) thru a corresponding STARTED class entry.

The following sample set of commands is shown here as a guideline:

rdef started IOAGATE.** uacc(none) owner(admin) audit(all(read)) stdata(user(IOAGATE) group(stc))

setr racl(started) ref"
  impact 0.5
  ref 'DPMS Target zOS BMC IOA for RACF'
  tag check_id: 'C-26098r518926_chk'
  tag severity: 'medium'
  tag gid: 'V-224421'
  tag rid: 'SV-224421r518928_rule'
  tag stig_id: 'ZIOAR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26086r518927_fix'
  tag 'documentable'
  tag legacy: ['SV-32181', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
