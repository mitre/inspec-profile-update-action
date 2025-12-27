control 'SV-204720' do
  title 'The application server must initiate session logging upon startup.'
  desc 'Session logging activities are developed, integrated, and used in consultation with legal counsel in accordance with applicable federal laws, Executive Orders, directives, policies, or regulations.'
  desc 'check', 'Review the application server product documentation and server configuration to determine if the application server initiates session logging on application server startup.

If the application server is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to initiate session logging on application server startup.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4840r282807_chk'
  tag severity: 'medium'
  tag gid: 'V-204720'
  tag rid: 'SV-204720r508029_rule'
  tag stig_id: 'SRG-APP-000092-AS-000053'
  tag gtitle: 'SRG-APP-000092'
  tag fix_id: 'F-4840r282808_fix'
  tag 'documentable'
  tag legacy: ['SV-46435', 'V-35148']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
