control 'SV-95543' do
  title 'AAA Services must be configured to automatically audit account disabling actions.'
  desc 'When application accounts are disabled, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to disable authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account disabling actions provides logging that can be used for forensic purposes.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to automatically audit account disabling actions.

If AAA Services are not configured to automatically audit account disabling actions, this is a finding.'
  desc 'fix', 'Configure AAA Services to automatically audit account disabling actions.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80569r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80833'
  tag rid: 'SV-95543r1_rule'
  tag stig_id: 'SRG-APP-000028-AAA-000110'
  tag gtitle: 'SRG-APP-000028-AAA-000110'
  tag fix_id: 'F-87687r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
