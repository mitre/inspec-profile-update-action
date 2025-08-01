control 'SV-233158' do
  title 'The container platform must notify system administrator and ISSO of account enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Sending notification of account enabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, applications must notify the appropriate individuals so they can investigate the event.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Determine if the container platform is configured to notify system administrator and ISSO of account enabling actions.

If the container platform is not configured to notify system administrator and ISSO of account enabling actions, this is a finding.'
  desc 'fix', 'Configure the container platform to notify system administrator and ISSO of account enabling actions.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36094r600961_chk'
  tag severity: 'medium'
  tag gid: 'V-233158'
  tag rid: 'SV-233158r600963_rule'
  tag stig_id: 'SRG-APP-000320-CTR-000750'
  tag gtitle: 'SRG-APP-000320'
  tag fix_id: 'F-36062r600962_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
