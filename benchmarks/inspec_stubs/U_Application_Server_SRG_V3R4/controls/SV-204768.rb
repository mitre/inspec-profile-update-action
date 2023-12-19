control 'SV-204768' do
  title 'The application server must provide a clustering capability.'
  desc 'This requirement is dependent upon system MAC and confidentiality. If the system MAC and confidentiality levels do not specify redundancy requirements, this requirement is NA.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. When application failure is encountered, preserving application state facilitates application restart and return to the operational mode of the organization with less disruption of mission/business processes.

Clustering of multiple application servers is a common approach to providing fail-safe application availability when system MAC and confidentiality levels require redundancy.'
  desc 'check', 'This requirement is dependent upon system MAC and confidentiality.

If the system MAC and confidentiality levels do not specify redundancy requirements, this requirement is NA.

Review the application server configuration and documentation to ensure the application server is configured to provide clustering functionality.

If the application server is not configured to provide clustering or some form of failover functionality, this is a finding.'
  desc 'fix', 'This requirement is dependent upon system MAC and confidentiality.

If the system MAC and confidentiality levels do not specify redundancy requirements, this requirement is NA.

Configure the application server to provide application failover or participate in an application cluster which provides failover.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4888r282951_chk'
  tag severity: 'medium'
  tag gid: 'V-204768'
  tag rid: 'SV-204768r879640_rule'
  tag stig_id: 'SRG-APP-000225-AS-000154'
  tag gtitle: 'SRG-APP-000225'
  tag fix_id: 'F-4888r282952_fix'
  tag 'documentable'
  tag legacy: ['V-35424', 'SV-46711']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
