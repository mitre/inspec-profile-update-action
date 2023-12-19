control 'SV-205517' do
  title 'The Mainframe Product must separate user functionality (including user interface services) from information system management functionality.'
  desc 'Application management functionality includes functions necessary for administration and requires privileged user access. Allowing non-privileged users to access application management functionality capabilities increases the risk that non-privileged users may obtain elevated privileges. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, different TCP/UDP ports, virtualization techniques, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. This may include isolating the administrative interface on a different security domain and with additional access controls.'
  desc 'check', 'Examine installation and configuration settings.

User module should be loaded into a separate dataset than system management modules.

If the Mainframe Product does not differentiate user functionality from product management functionality, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to load user modules into a separate dataset than system management modules.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5783r299784_chk'
  tag severity: 'medium'
  tag gid: 'V-205517'
  tag rid: 'SV-205517r397711_rule'
  tag stig_id: 'SRG-APP-000211-MFP-000283'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-5783r299785_fix'
  tag 'documentable'
  tag legacy: ['SV-82947', 'V-68457']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
