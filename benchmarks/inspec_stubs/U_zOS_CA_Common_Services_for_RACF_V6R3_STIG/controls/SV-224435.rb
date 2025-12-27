control 'SV-224435' do
  title 'CA Common Services Started task will be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources. Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

- DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

- PDI(ZCCS0032)

If the CA Common Services started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry, this is not a finding.'
  desc 'fix', 'The ISSO working with the systems programmer will ensure the CA Common Services Started Task(s) is properly identified and/or defined to the System ACP. 

A unique userid must be assigned for the CA Common Services started task(s) thru a corresponding STARTED class entry.

The following commands are provided as a sample for defining Started Task(s):

rdef started CAS9.** uacc(none) owner(admin) audit(all(read)) -
	stdata(user(CAS9) group(stc))
setr racl(started) ref'
  impact 0.5
  ref 'DPMS Target zOS CA Common Services for RACF'
  tag check_id: 'C-26112r868320_chk'
  tag severity: 'medium'
  tag gid: 'V-224435'
  tag rid: 'SV-224435r868322_rule'
  tag stig_id: 'ZCCSR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26100r868321_fix'
  tag 'documentable'
  tag legacy: ['V-17454', 'SV-40859']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
