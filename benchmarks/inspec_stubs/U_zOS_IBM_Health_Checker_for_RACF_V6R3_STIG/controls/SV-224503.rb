control 'SV-224503' do
  title 'IBM Health Checker Started task will be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources. Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

- DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

- PDI(ZHCK0032)

If the IBM Health Checker started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry, this is not a finding.'
  desc 'fix', 'The ISSO working with the systems programmer will ensure the IBM Health Checker Started Task(s) is properly identified and/or defined to the System ACP. 

A unique userid must be assigned for the IBM Health Checker started task(s) thru a corresponding STARTED class entry.

The following commands are provided as a sample for defining Started Task(s):

rdef started HZSPROC.** uacc(none) owner(admin) audit(all(read)) -
	stdata(user(HXSPROC) group(stc))
setr racl(started) ref'
  impact 0.5
  ref 'DPMS Target zOS IBM Health Checker for RACF'
  tag check_id: 'C-26186r868417_chk'
  tag severity: 'medium'
  tag gid: 'V-224503'
  tag rid: 'SV-224503r868419_rule'
  tag stig_id: 'ZHCKR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26174r868418_fix'
  tag 'documentable'
  tag legacy: ['SV-43187', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
