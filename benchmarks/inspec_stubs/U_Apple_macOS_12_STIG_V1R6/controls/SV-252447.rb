control 'SV-252447' do
  title 'The macOS system must be integrated into a directory services infrastructure.'
  desc 'Distinct user account databases on each separate system cause problems with username and password policy enforcement. Most approved directory services infrastructure solutions allow centralized management of users and passwords.'
  desc 'check', 'If the system is using a mandatory Smart Card Policy, this is Not Applicable. 

To determine if the system is integrated to a directory service, run the following command:

/usr/bin/dscl localhost -list . | /usr/bin/grep "Active Directory"

If no results are returned, this is a finding.'
  desc 'fix', 'Integrate the system into an existing directory services infrastructure.'
  impact 0.7
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55903r816153_chk'
  tag severity: 'high'
  tag gid: 'V-252447'
  tag rid: 'SV-252447r816155_rule'
  tag stig_id: 'APPL-12-000016'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55853r816154_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
