control 'SV-204708' do
  title 'The application server must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'Application management includes the ability to control the number of sessions that utilize an application by all accounts and/or account types. Limiting the number of allowed sessions is helpful in limiting risks related to Denial of Service attacks.

Application servers host and expose business logic and application processes.

The application server must possess the capability to limit the maximum number of concurrent sessions in a manner that affects the entire application server or on an individual application basis.

Although there is some latitude concerning the settings themselves, the settings should follow DoD-recommended values, but the settings should be configurable to allow for future DoD direction.

While the DoD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', 'Review the application server product documentation and configuration to determine if the number of concurrent sessions can be limited to the organization-defined number of sessions for all accounts and/or account types.

If a feature to limit the number of concurrent sessions is not available, is not set, or is set to unlimited, this is a finding.'
  desc 'fix', 'Configure the application server to limit the number of concurrent sessions for all accounts and/or account types to the organization-defined number.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4828r282771_chk'
  tag severity: 'medium'
  tag gid: 'V-204708'
  tag rid: 'SV-204708r879511_rule'
  tag stig_id: 'SRG-APP-000001-AS-000001'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-4828r282772_fix'
  tag 'documentable'
  tag legacy: ['SV-46335', 'V-35070']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
