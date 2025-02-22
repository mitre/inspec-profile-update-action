control 'SV-206518' do
  title 'Analysis, viewing, and indexing functions, services, and applications used as part of the Central Log Server must be configured to comply with DoD-trusted path and access requirements.'
  desc 'Analysis, viewing, and indexing functions, services, and applications, such as analysis tools and other vendor-provided applications, must be secured. Software used to perform additional functions, which resides on the server, must also be secured or could provide a vector for unauthorized access to the events repository.'
  desc 'check', 'Examine the configuration.

Verify analysis, viewing, and indexing functions, services, and applications used with the Central Log Server are configured to comply with DoD-trusted path and access requirements.

If analysis, viewing, and indexing functions, services, and applications used with the Central Log Server are not configured to comply with DoD-trusted path and access requirements, this is a finding.'
  desc 'fix', 'Configure all analysis, viewing, and indexing functions, services, and applications used with the Central Log Server to comply with DoD-trusted path and access requirements.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6778r285795_chk'
  tag severity: 'medium'
  tag gid: 'V-206518'
  tag rid: 'SV-206518r401224_rule'
  tag stig_id: 'SRG-APP-000516-AU-000410'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-6778r285796_fix'
  tag 'documentable'
  tag legacy: ['SV-95905', 'V-81191']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
