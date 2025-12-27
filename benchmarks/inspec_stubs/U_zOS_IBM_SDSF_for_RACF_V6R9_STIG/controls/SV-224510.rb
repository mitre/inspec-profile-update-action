control 'SV-224510' do
  title 'IBM System Display and Search Facility (SDSF) Started task will be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources. Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZISF0032)

If the IBM SDSF started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry, this is not a finding.'
  desc 'fix', 'The ISSO working with the systems programmer will ensure the IBM SDSF Started Task(s) is properly identified and/or defined to the System ACP.

A unique userid must be assigned for the IBM SDSF started task(s) thru a corresponding STARTED class entry.

The following commands are provided as a sample for defining Started Task(s):

rdef started SDSF.** uacc(none) owner(admin) audit(all(read)) –
	stdata(user(SDSF) group(stc))
setr racl(started) ref'
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for RACF'
  tag check_id: 'C-26193r840221_chk'
  tag severity: 'medium'
  tag gid: 'V-224510'
  tag rid: 'SV-224510r840223_rule'
  tag stig_id: 'ZISFR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26181r840222_fix'
  tag 'documentable'
  tag legacy: ['SV-40824', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
