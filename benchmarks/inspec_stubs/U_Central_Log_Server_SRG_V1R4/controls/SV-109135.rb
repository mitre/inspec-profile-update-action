control 'SV-109135' do
  title 'The Central Log Server must automatically audit account removal actions.'
  desc 'When application accounts are removed, user accessibility is affected. Once an attacker establishes access to an application, the attacker often attempts to remove authorized accounts to disrupt services or prevent the implementation of countermeasures. Auditing account removal actions provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to automatically audit account removal.

If the Central Log Server is not configured to automatically audit account removal, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to automatically audit account removal.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-98881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-100031'
  tag rid: 'SV-109135r1_rule'
  tag stig_id: 'SRG-APP-000029-AU-000610'
  tag gtitle: 'SRG-APP-000029-AU-000610'
  tag fix_id: 'F-105715r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
