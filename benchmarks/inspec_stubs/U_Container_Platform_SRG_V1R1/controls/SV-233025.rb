control 'SV-233025' do
  title 'The container platform must automatically audit account removal actions.'
  desc 'When application accounts are removed, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to remove authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account removal actions provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the container platform configuration to determine if account removal is automatically audited. 

If account removal is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the container platform to automatically audit account removal.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35961r598711_chk'
  tag severity: 'medium'
  tag gid: 'V-233025'
  tag rid: 'SV-233025r599509_rule'
  tag stig_id: 'SRG-APP-000029-CTR-000085'
  tag gtitle: 'SRG-APP-000029'
  tag fix_id: 'F-35929r598712_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
