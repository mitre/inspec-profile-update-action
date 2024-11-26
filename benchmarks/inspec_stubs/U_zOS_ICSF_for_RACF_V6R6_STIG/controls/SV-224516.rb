control 'SV-224516' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Started task(s) must be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZICS0032)

Verify that the IBM Integrated Crypto Service Facility (ICSF) started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry.'
  desc 'fix', "The IBM Integrated Crypto Service Facility (ICSF) system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP.  

A unique userid must be assigned for the IBM Integrated Crypto Service Facility (ICSF) started task(s) thru a corresponding STARTED class entry.

The following sample set of commands is shown here as a guideline:

rdef started CSFSTART.** uacc(none) owner(admin) audit(all(read)) stdata(user(CSFSTART) group(stc))

setr racl(started) ref"
  impact 0.5
  ref 'DPMS Target zOS ICSF for RACF'
  tag check_id: 'C-26199r520409_chk'
  tag severity: 'medium'
  tag gid: 'V-224516'
  tag rid: 'SV-224516r520411_rule'
  tag stig_id: 'ZICSR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26187r520410_fix'
  tag 'documentable'
  tag legacy: ['SV-30579', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
