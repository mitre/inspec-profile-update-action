control 'SV-257153' do
  title 'The macOS system must be integrated into a directory services infrastructure.'
  desc 'Distinct user account databases on each separate system cause problems with username and password policy enforcement. Most approved directory services infrastructure solutions allow centralized management of users and passwords.'
  desc 'check', 'If the macOS system is using a mandatory Smart Card Policy, this requirement is not applicable.

Verify the macOS system is configured to integrate into a directory service with the following command:

/usr/bin/dscl localhost -list . | /usr/bin/grep "Active Directory"

If no results are returned, this is a finding.'
  desc 'fix', 'Configure the macOS system to integrate into an existing directory services infrastructure.'
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60838r905090_chk'
  tag severity: 'high'
  tag gid: 'V-257153'
  tag rid: 'SV-257153r905092_rule'
  tag stig_id: 'APPL-13-000016'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60779r905091_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
