control 'SV-224540' do
  title 'IBM Tivoli Asset Discovery for zOS (TADz) Started task(s) must be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	DSMON.RPT(RACSPT)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZTAD0032)

Verify that the IBM Tivoli Asset Discovery for zOS (TADz) started task(s) is (are) defined to the STARTED resource class profile and/or ICHRIN03 table entry.'
  desc 'fix', "The IBM Tivoli Asset Discovery for zOS (TADz) system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP.  

A unique userid must be assigned for the IBM Tivoli Asset Discovery for zOS (TADz) started task(s) thru a corresponding STARTED class entry.

The following sample set of commands is shown here as a guideline:

rdef started TADZMON.** uacc(none) owner(admin) audit(all(read)) stdata(user(TADZMON) group(stc))

setr racl(started) ref"
  impact 0.5
  ref 'DPMS Target zOS TADz for RACF'
  tag check_id: 'C-26223r520907_chk'
  tag severity: 'medium'
  tag gid: 'V-224540'
  tag rid: 'SV-224540r520909_rule'
  tag stig_id: 'ZTADR032'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26211r520908_fix'
  tag 'documentable'
  tag legacy: ['SV-28561', 'V-17454']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
