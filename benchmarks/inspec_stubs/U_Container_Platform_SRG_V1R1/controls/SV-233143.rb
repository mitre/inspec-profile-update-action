control 'SV-233143' do
  title 'The container platform must notify system administrators and ISSO when accounts are created.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Sending notification of account creation events to the system administrator and ISSO is one method for mitigating this risk.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the container platform configuration to determine if system administrators and ISSO are notified when accounts are created. 

If system administrators and ISSO are not notified, this is a finding.'
  desc 'fix', 'Configure the container platform to notify system administrators and ISSO when accounts are created.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36079r599065_chk'
  tag severity: 'medium'
  tag gid: 'V-233143'
  tag rid: 'SV-233143r599509_rule'
  tag stig_id: 'SRG-APP-000291-CTR-000675'
  tag gtitle: 'SRG-APP-000291'
  tag fix_id: 'F-36047r599066_fix'
  tag 'documentable'
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
