control 'SV-252895' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Started task(s) must be properly defined to the Started Task Table ACID for Top Secret.'
  desc 'Access to product resources should be restricted to only those individuals responsible for the application connectivity and who have a requirement to access these resources.  Improper control of product resources could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'from the ISPF Command Shell enter

TSS LIST(STC)


If the IBM Integrated Crypto Service Facility (ICSF) started task(s) is (are) not defined in the TSS STC record this is a finding.'
  desc 'fix', "The IBM Integrated Crypto Service Facility (ICSF) system programmer and the IAO will ensure that a product's started task(s) is (are) properly identified and/or defined to the System ACP. 

A unique ACID must be assigned for the IBM Integrated Crypto Service Facility (ICSF) started task(s) thru a corresponding STC table entry.

The following sample set of commands is shown here as a guideline:

TSS ADD(STC) PROCNAME(CSFSTART) ACID(CSFSTART)"
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-56351r822572_chk'
  tag severity: 'medium'
  tag gid: 'V-252895'
  tag rid: 'SV-252895r822574_rule'
  tag stig_id: 'TSS0-IC-000050'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-56301r822573_fix'
  tag 'documentable'
  tag legacy: ['V-17454', 'SV-30580']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
