control 'SV-233024' do
  title 'The container platform must automatically audit account-disabling actions.'
  desc 'When application accounts are disabled, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to disable authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account-disabling actions provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the container platform configuration to determine if account disabling is automatically audited. 

If account disabling is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the container platform to automatically audit account disabling.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35960r600559_chk'
  tag severity: 'medium'
  tag gid: 'V-233024'
  tag rid: 'SV-233024r600561_rule'
  tag stig_id: 'SRG-APP-000028-CTR-000080'
  tag gtitle: 'SRG-APP-000028'
  tag fix_id: 'F-35928r600560_fix'
  tag 'documentable'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
