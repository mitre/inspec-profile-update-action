control 'SV-90855' do
  title 'The OS X system must be integrated into a directory services infrastructure.'
  desc 'Distinct user account databases on each separate system cause problems with username and password policy enforcement. Most approved directory services infrastructure solutions allow centralized management of users and passwords.'
  desc 'check', "To determine if the system is integrated to a directory service, ask the System Administrator (SA) or Information System Security Officer (ISSO) or run the following command:

/usr/bin/sudo dscl localhost -list . | /usr/bin/grep -vE '(Contact | Search | Local)'

If nothing is returned, or if the system is not integrated into a directory service infrastructure, this is a finding."
  desc 'fix', 'Integrate the system into an existing directory services infrastructure.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75853r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76167'
  tag rid: 'SV-90855r1_rule'
  tag stig_id: 'AOSX-12-002060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82805r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
