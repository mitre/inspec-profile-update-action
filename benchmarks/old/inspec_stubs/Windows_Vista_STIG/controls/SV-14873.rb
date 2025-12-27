control 'SV-14873' do
  title 'IPv6 must be disabled until a deliberate transition strategy has been implemented.  Use of IPv6 transition technologies must be disabled.'
  desc 'Any nodes’ interface with IPv6 enabled by default presents a potential risk of traffic being transmitted or received without proper risk mitigation strategy and is therefore, a serious security concern.'
  desc 'fix', 'Add the following registry values to the system.

To disable IPv6 on all interfaces:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\

Value Name:  DisabledComponents

Type:  REG_DWORD
Value:  0xff or 0xffffffff

To disable all IPv6 tunneling interfaces:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\

Value Name:  DisabledComponents

Type:  REG_DWORD
Value:  0x1

Microsoft updated article 929852 with regard to disabling all IPv6 components, changing the value to 0xff.   A value of 0xffffffff results in a 5-second delay in system startup.  However, either value can be used to disable all IPv6 components.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14262'
  tag rid: 'SV-14873r3_rule'
  tag gtitle: 'IPv6 Transition'
  tag fix_id: 'F-62369r2_fix'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
