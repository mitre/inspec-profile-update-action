control 'SV-234287' do
  title 'The UEM server must automatically remove or disable temporary user accounts after 72 hours if supported by the UEM server.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary user accounts must be set upon account creation.

Temporary user accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation. 

If temporary user accounts are used, the application must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Requirement is Not Applicable when the UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server automatically removes or disables temporary user accounts after 72 hours, if supported by the UEM server.

If the UEM server does not automatically remove or disable temporary user accounts after 72 hours, if supported by the UEM server, this is a finding.'
  desc 'fix', 'Configure the UEM server to automatically remove or disable temporary user accounts after 72 hours, if supported by the UEM server.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37472r613871_chk'
  tag severity: 'medium'
  tag gid: 'V-234287'
  tag rid: 'SV-234287r617355_rule'
  tag stig_id: 'SRG-APP-000024-UEM-000013'
  tag gtitle: 'SRG-APP-000024'
  tag fix_id: 'F-37437r613872_fix'
  tag 'documentable'
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
