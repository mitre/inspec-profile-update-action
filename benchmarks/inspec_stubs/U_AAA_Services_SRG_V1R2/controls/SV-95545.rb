control 'SV-95545' do
  title 'AAA Services must be configured to automatically audit account removal actions.'
  desc 'When application accounts are removed, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to remove authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account removal actions provides logging that can be used for forensic purposes.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to automatically audit account removal actions.

If AAA Services are not configured to automatically audit account removal actions, this is a finding.'
  desc 'fix', 'Configure AAA Services to automatically audit account removal actions.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80571r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80835'
  tag rid: 'SV-95545r1_rule'
  tag stig_id: 'SRG-APP-000029-AAA-000120'
  tag gtitle: 'SRG-APP-000029-AAA-000120'
  tag fix_id: 'F-87689r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
