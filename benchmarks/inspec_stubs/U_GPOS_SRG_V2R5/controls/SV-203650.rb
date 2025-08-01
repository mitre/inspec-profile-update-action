control 'SV-203650' do
  title 'The operating system must uniquely identify and must authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication and identification enables non-organizational users to gain access to the application or possibly other information systems and provides an opportunity for intruders to compromise resources within the application or information system.

Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of an employee (e.g., contractors and guest researchers).

Non-organizational users shall be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access.'
  desc 'check', 'Verify the operating system uniquely identifies and authenticates non-organizational users (or processes acting on behalf of non-organizational users). If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3775r557195_chk'
  tag severity: 'medium'
  tag gid: 'V-203650'
  tag rid: 'SV-203650r557197_rule'
  tag stig_id: 'SRG-OS-000121-GPOS-00062'
  tag gtitle: 'SRG-OS-000121'
  tag fix_id: 'F-3775r557196_fix'
  tag 'documentable'
  tag legacy: ['V-56791', 'SV-71051']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
