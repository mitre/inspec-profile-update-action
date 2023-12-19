control 'SV-224477' do
  title 'Compuware Abend-AID Started task will be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources. Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

- DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

- PDI(ZAID0032)

If the Compuware Abend-AID started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry, this is not a finding.'
  desc 'fix', 'The ISSO working with the systems programmer will ensure the Compuware Abend-AID Started Task(s) is properly identified and/or defined to the System ACP. 

A unique userid must be assigned for the Compuware Abend-AID started task(s) thru a corresponding STARTED class entry.

The following commands are provided as a sample for defining Started Task(s):

rdef started AAVIEWER.** uacc(none) owner(admin) audit(all(read)) -
	stdata(user(AAVIEWER) group(stc))
rdef started BDCAS.** uacc(none) owner(admin) audit(all(read)) -
	stdata(user(BDCAS) group(stc))
rdef started TDCAS.** uacc(none) owner(admin) audit(all(read)) -
	stdata(user(TDCAS) group(stc))
setr racl(started) ref'
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for RACF'
  tag check_id: 'C-26160r868293_chk'
  tag severity: 'medium'
  tag gid: 'V-224477'
  tag rid: 'SV-224477r868295_rule'
  tag stig_id: 'ZAIDR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26148r868294_fix'
  tag 'documentable'
  tag legacy: ['SV-43185', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
