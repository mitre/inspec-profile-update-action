control 'SV-237922' do
  title 'CA VM:Secure product ADMIN GLOBALS command must be restricted to systems programming personnel.'
  desc 'Operating system management functionality includes functions necessary for administration and requires privileged user access. Allowing non-privileged users to access operating system management functionality capabilities increases the risk that non-privileged users may obtain elevated privileges.

Operating system management functionality includes functions necessary to administer console, network components, workstations, or servers and typically requires privileged user access.

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, different TCP/UDP ports, virtualization techniques, combinations of these methods, or other methods, as appropriate.

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. This may include isolating the administrative interface on a different security domain and with additional access controls.'
  desc 'check', 'Examine the “AUTHORIZ” config file.

If authorization to “ADMIN GLOBALS” is granted to “SYS Admin”, this is not a finding.'
  desc 'fix', 'Configure grant statements in the “AUTHORIZ” file using the “ADMIN GLOBALS” command that list Sys Admins only.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41132r649604_chk'
  tag severity: 'medium'
  tag gid: 'V-237922'
  tag rid: 'SV-237922r649606_rule'
  tag stig_id: 'IBMZ-VM-000690'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-41091r649605_fix'
  tag 'documentable'
  tag legacy: ['SV-93597', 'V-78891']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
