control 'SV-252890' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Started task(s) must be properly defined to the STARTED resource class for RACF.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Execute the RACF DSMON report for RACSPT

if the IBM Integrated Crypto Service Facility (ICSF) started task(s) is (are)  not defined to the STARTED resource class profile and/or ICHRIN03 table entry this is a finding'
  desc 'fix', "Ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP.  

A unique userid must be assigned for the IBM Integrated Crypto Service Facility (ICSF) started task(s) thru a corresponding STARTED class entry.

The following sample set of commands is shown here as a guideline:

rdef started CSFSTART.** uacc(none) owner(admin) audit(all(read)) stdata(user(CSFSTART) group(stc))

setr racl(started) ref"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-56346r822557_chk'
  tag severity: 'medium'
  tag gid: 'V-252890'
  tag rid: 'SV-252890r864493_rule'
  tag stig_id: 'RACF-IC-000050'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-56296r822558_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
