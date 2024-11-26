control 'SV-248588' do
  title 'OL 8 must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access. 
 
The DoD has mandated the use of the Common Access Card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', 'Verify OL 8 accepts PIV credentials. 
 
Check that the "opensc" package is installed on the system with the following command: 
 
$ sudo yum list installed opensc 
 
opensc.x86_64     0.19.0-5.el8     @anaconda 
 
Check that "opensc" accepts PIV cards with the following command: 
 
$ sudo opensc-tool --list-drivers | grep -i piv 
 
  PIV-II     Personal Identity Verification Card 
 
If the "opensc" package is not installed and the "opensc-tool" driver list does not include "PIV-II", this is a finding.'
  desc 'fix', 'Configure OL 8 to accept PIV credentials. 
 
Install the "opensc" package using the following command: 
 
$ sudo yum install opensc'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52022r779328_chk'
  tag severity: 'medium'
  tag gid: 'V-248588'
  tag rid: 'SV-248588r853769_rule'
  tag stig_id: 'OL08-00-010410'
  tag gtitle: 'SRG-OS-000376-GPOS-00161'
  tag fix_id: 'F-51976r779329_fix'
  tag 'documentable'
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
