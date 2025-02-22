control 'SV-71095' do
  title 'The operating system must separate user functionality (including user interface services) from operating system management functionality.'
  desc 'Operating system management functionality includes functions necessary for administration and requires privileged user access. Allowing non-privileged users to access operating system management functionality capabilities increases the risk that non-privileged users may obtain elevated privileges.

Operating system management functionality includes functions necessary to administer console, network components, workstations, or servers and typically requires privileged user access.

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, different TCP/UDP ports, virtualization techniques, combinations of these methods, or other methods, as appropriate.

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. This may include isolating the administrative interface on a different security domain and with additional access controls.'
  desc 'check', 'Verify the operating system separates user functionality (including user interface services) from operating system management functionality. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to separate user functionality (including user interface services) from operating system management functionality.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57405r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56835'
  tag rid: 'SV-71095r1_rule'
  tag stig_id: 'SRG-OS-000132-GPOS-00067'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-61731r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
