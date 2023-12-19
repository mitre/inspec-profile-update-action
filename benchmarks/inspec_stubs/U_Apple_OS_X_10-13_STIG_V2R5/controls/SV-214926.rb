control 'SV-214926' do
  title 'The macOS system must be integrated into a directory services infrastructure.'
  desc 'Distinct user account databases on each separate system cause problems with username and password policy enforcement. Most approved directory services infrastructure solutions allow centralized management of users and passwords.'
  desc 'check', "To determine if the system is integrated to a directory service, ask the System Administrator (SA) or Information System Security Officer (ISSO) or run the following command:

/usr/bin/sudo dscl localhost -list . | /usr/bin/grep -vE '(Contact | Search | Local)'

If nothing is returned, or if the system is not integrated into a directory service infrastructure, this is a finding."
  desc 'fix', 'Integrate the system into an existing directory services infrastructure.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16126r397350_chk'
  tag severity: 'high'
  tag gid: 'V-214926'
  tag rid: 'SV-214926r609363_rule'
  tag stig_id: 'AOSX-13-002060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16124r397351_fix'
  tag 'documentable'
  tag legacy: ['SV-96447', 'V-81733']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
