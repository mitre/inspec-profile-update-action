control 'SV-253090' do
  title 'TOSS must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

The DoD has mandated the use of the Common Access Card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', 'Verify TOSS accepts PIV credentials.

Check that the "opensc" package is installed on the system with the following command:

$ sudo yum list installed opensc

opensc.x86_64 0.20.0-4.el8 @anaconda

Check that "opensc" accepts PIV cards with the following command:

$ sudo opensc-tool --list-drivers | grep -i piv

PIV-II Personal Identity Verification Card

If the "opensc" package is not installed and the "opensc-tool" driver list does not include "PIV-II", this is a finding.'
  desc 'fix', 'Configure TOSS to accept PIV credentials.

Install the "opensc" package using the following command:

$ sudo yum install opensc'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56543r824940_chk'
  tag severity: 'medium'
  tag gid: 'V-253090'
  tag rid: 'SV-253090r824942_rule'
  tag stig_id: 'TOSS-04-040420'
  tag gtitle: 'SRG-OS-000376-GPOS-00161'
  tag fix_id: 'F-56493r824941_fix'
  tag 'documentable'
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
