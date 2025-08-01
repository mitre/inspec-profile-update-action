control 'SV-224480' do
  title 'IBM CSSMTP Started task(s) must be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZSMT0032)

Verify that the IBM CSSMTP started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry.'
  desc 'fix', "The IBM CSSMTP system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique userid must be assigned for the IBM CSSMTP started task(s) thru a corresponding STARTED class entry.

The following sample set of commands is shown here as a guideline:

rdef started CSSMTP.** uacc(none) owner(admin) audit(all(read)) stdata(user(CSSMTP) group(stc))

setr racl(started) ref"
  impact 0.5
  ref 'DPMS Target zOS CSSMTP for RACF'
  tag check_id: 'C-26163r519866_chk'
  tag severity: 'medium'
  tag gid: 'V-224480'
  tag rid: 'SV-224480r519868_rule'
  tag stig_id: 'ZSMTR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26151r519867_fix'
  tag 'documentable'
  tag legacy: ['SV-37483', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
