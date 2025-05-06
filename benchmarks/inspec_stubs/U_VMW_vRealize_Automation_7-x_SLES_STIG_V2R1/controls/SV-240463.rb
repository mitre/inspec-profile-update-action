control 'SV-240463' do
  title 'The SLES for vRealize must uniquely identify and must authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication and identification enables non-organizational users to gain access to the application or possibly other information systems and provides an opportunity for intruders to compromise resources within the application or information system.

Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of an employee (e.g., contractors and guest researchers).

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access.'
  desc 'check', 'Run the following command to check for duplicate account names: 

# pwck -rq

If there are no duplicate names, no line will be returned. 

If a line is returned, this is a finding.'
  desc 'fix', 'Change usernames, or delete accounts, so each has a unique name.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43696r671128_chk'
  tag severity: 'medium'
  tag gid: 'V-240463'
  tag rid: 'SV-240463r671130_rule'
  tag stig_id: 'VRAU-SL-000735'
  tag gtitle: 'SRG-OS-000121-GPOS-00062'
  tag fix_id: 'F-43655r671129_fix'
  tag 'documentable'
  tag legacy: ['SV-100353', 'V-89703']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
