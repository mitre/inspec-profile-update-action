control 'SV-222574' do
  title 'The application user interface must be either physically or logically separated from data storage and management interfaces.'
  desc 'Application management functionality includes functions necessary for administration and requires privileged user access. Allowing non-privileged users to access application management functionality capabilities increases the risk that non-privileged users may obtain elevated privileges.

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, different TCP/UDP ports, virtualization techniques, combinations of these methods, or other methods, as appropriate.

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. This may include isolating the administrative interface on a different security domain and with additional access controls.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Review the design documents and the interfaces used by the application.

Verify that the application provides separate interfaces for user traffic and for management traffic. The separation may be virtual in nature (virtual host, virtual NIC, virtual network) or physically separate.

If the application user interface and the application management interface are shared, this is a finding.'
  desc 'fix', 'Configure the application so user interface to the application and management interface to the application is separated.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24244r493630_chk'
  tag severity: 'medium'
  tag gid: 'V-222574'
  tag rid: 'SV-222574r508029_rule'
  tag stig_id: 'APSC-DV-002150'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-24233r493631_fix'
  tag 'documentable'
  tag legacy: ['V-70199', 'SV-84821']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
