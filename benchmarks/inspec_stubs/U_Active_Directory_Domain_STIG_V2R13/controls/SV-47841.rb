control 'SV-47841' do
  title 'Delegation of privileged accounts must be prohibited.'
  desc 'Privileged accounts such as those belonging to any of the administrator groups must not be trusted for delegation. Allowing privileged accounts to be trusted for delegation provides a means for privilege escalation from a compromised system.'
  desc 'check', 'Review the properties of all privileged accounts in Active Directory Users and Computers. Under the Account tab, verify "Account is sensitive and cannot be delegated" is selected in the Account Options section. If delegation is not prohibited for any  privileged account, this is a finding.'
  desc 'fix', 'Open Active Directory Users and Computers. View the properties of all privileged accounts. Under the Account tab, select "Account is sensitive and cannot be delegated" in the Account Options section.'
  impact 0.7
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-44677r1_chk'
  tag severity: 'high'
  tag gid: 'V-36435'
  tag rid: 'SV-47841r2_rule'
  tag stig_id: 'AD.0005'
  tag gtitle: 'Delegation of Privileged Accounts'
  tag fix_id: 'F-40967r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
