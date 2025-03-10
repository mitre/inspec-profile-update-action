control 'SV-207401' do
  title 'The VMM must separate user functionality (including user interface services) from VMM management functionality.'
  desc 'VMM management functionality includes functions necessary for administration and requires privileged user access. Allowing non-privileged users to access VMM management functionality capabilities increases the risk that non-privileged users may obtain elevated privileges. 

VMM management functionality includes functions necessary to administer console, network components, workstations, or servers, and typically requires privileged user access. 

The separation of user functionality from VMM management functionality is either physical or logical and is accomplished by using different guest VMs, different computers, different central processing units, different instances of the VMM, different network addresses, different TCP/UDP ports, other virtualization techniques, combinations of these methods, or other methods, as appropriate.'
  desc 'check', 'Verify the VMM separates user functionality (including user interface services) from VMM management functionality.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to separate user functionality (including user interface services) from VMM management functionality.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7658r365613_chk'
  tag severity: 'medium'
  tag gid: 'V-207401'
  tag rid: 'SV-207401r378967_rule'
  tag stig_id: 'SRG-OS-000132-VMM-000650'
  tag gtitle: 'SRG-OS-000132'
  tag fix_id: 'F-7658r365614_fix'
  tag 'documentable'
  tag legacy: ['SV-71263', 'V-57003']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
