control 'SV-100357' do
  title 'The SLES for vRealize must uniquely identify and must authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication and identification enables non-organizational users to gain access to the application or possibly other information systems and provides an opportunity for intruders to compromise resources within the application or information system.

Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of an employee (e.g., contractors and guest researchers).

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access.'
  desc 'check', "Verify the SLES for vRealize uniquely identifies and authenticates non-organizational users by running the following commands:

# awk -F: '{print $3}' /etc/passwd | sort | uniq -d

If the output is not blank, this is a finding."
  desc 'fix', 'Configure the SLES for vRealize to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

UNIQUE_USER_ID is a unique numerical value that must be non-negative. USERNAME is the username of the user whose user ID is to be changed.

# usermod -u [UNIQUE_USER_ID] [USERNAME]'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89399r2_chk'
  tag severity: 'medium'
  tag gid: 'V-89707'
  tag rid: 'SV-100357r1_rule'
  tag stig_id: 'VRAU-SL-000745'
  tag gtitle: 'SRG-OS-000121-GPOS-00062'
  tag fix_id: 'F-96449r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
