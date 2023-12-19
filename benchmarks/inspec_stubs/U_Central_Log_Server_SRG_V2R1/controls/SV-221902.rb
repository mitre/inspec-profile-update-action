control 'SV-221902' do
  title 'The Central Log Server must automatically audit account disabling actions.'
  desc 'When application accounts are disabled, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to disable authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account disabling actions provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to automatically audit account disabling.

If the Central Log Server is not configured to automatically audit account disabling, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to automatically audit account disabling.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23617r420048_chk'
  tag severity: 'medium'
  tag gid: 'V-221902'
  tag rid: 'SV-221902r420050_rule'
  tag stig_id: 'SRG-APP-000028-AU-000600'
  tag gtitle: 'SRG-APP-000028'
  tag fix_id: 'F-23606r420049_fix'
  tag 'documentable'
  tag legacy: ['SV-109133', 'V-100029']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
