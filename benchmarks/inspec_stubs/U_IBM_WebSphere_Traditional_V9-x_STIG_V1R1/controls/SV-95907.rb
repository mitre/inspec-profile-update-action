control 'SV-95907' do
  title 'The WebSphere Application Server maximum in-memory session count must be set according to application requirements.'
  desc 'Application management includes the ability to control the number of sessions that utilize an application by all accounts and/or account types. Limiting the number of allowed sessions is helpful in limiting risks related to Denial of Service attacks.

Application servers host and expose business logic and application processes.

The application server must possess the capability to limit the maximum number of concurrent sessions in a manner that affects the entire application server or on an individual application basis.

Although there is some latitude concerning the settings themselves, the settings should follow DoD-recommended values, but the settings should be configurable to allow for future DoD direction.

While the DoD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', 'Review system documentation.

Identify the application session requirements.

In the administrative console page, click Servers >> Server Types >> WebSphere application servers >> [server_name] >> Session management.

Ensure the Maximum in-memory session count field is set to the number of sessions allowable.

If not set according to application requirements, this is a finding.'
  desc 'fix', 'In the administrative console page, click Servers >> Server Types >> WebSphere application servers >> [server_name] >> Session management.

Edit the Maximum in-memory session count field to be the number of sessions allowable.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81193'
  tag rid: 'SV-95907r1_rule'
  tag stig_id: 'WBSP-AS-000010'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag fix_id: 'F-87971r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
