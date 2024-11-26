control 'SV-221921' do
  title 'The Central Log Server must notify system administrators and ISSO when accounts are created.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Sending notification of account creation events to the system administrator and ISSO is one method for mitigating this risk.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to notify system administrators and the ISSO when accounts are created.

If the Central Log Server is not configured to notify system administrators and ISSO when accounts are created, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to notify system administrators and the ISSO when accounts are created.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23636r420105_chk'
  tag severity: 'low'
  tag gid: 'V-221921'
  tag rid: 'SV-221921r420107_rule'
  tag stig_id: 'SRG-APP-000291-AU-000200'
  tag gtitle: 'SRG-APP-000291'
  tag fix_id: 'F-23625r420106_fix'
  tag 'documentable'
  tag legacy: ['SV-109125', 'V-100021']
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
