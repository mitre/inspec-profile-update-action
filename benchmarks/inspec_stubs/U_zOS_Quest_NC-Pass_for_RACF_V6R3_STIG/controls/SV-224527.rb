control 'SV-224527' do
  title 'Quest NC-Pass Started task will be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources. Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

- DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

- PDI(ZNCP0032)

If the Quest NC-Pass started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry, this is not a finding.'
  desc 'fix', 'The ISSO working with the systems programmer will ensure the Quest NC-Pass Started Task(s) is properly identified and/or defined to the System ACP.

A unique ACID must be assigned for the CA 1 Tape Management started task(s) thru a corresponding STC table entry.

The following commands are provided as a sample for defining Started Task(s):

rdef started NCPASS.** uacc(none) owner(admin) audit(all(read)) -
	stdata(user(NCPASS) group(stc))
setr racl(started) ref'
  impact 0.5
  ref 'DPMS Target zOS Quest NC-Pass for RACF'
  tag check_id: 'C-26210r868522_chk'
  tag severity: 'medium'
  tag gid: 'V-224527'
  tag rid: 'SV-224527r868527_rule'
  tag stig_id: 'ZNCPR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26198r868525_fix'
  tag 'documentable'
  tag legacy: ['SV-40875', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
