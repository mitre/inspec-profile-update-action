control 'SV-204782' do
  title 'The application server must control remote access methods.'
  desc 'Application servers provide remote access capability and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements.  Automated monitoring and control of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by logging connection activities of remote users.

Examples of policy requirements include, but are not limited to, authorizing remote access to the information system, limiting access based on authentication credentials, and monitoring for unauthorized access.'
  desc 'check', "Review organization policy, application server product documentation and configuration to determine if the system enforces the organization's requirements for remote connections.

If the system is not configured to enforce these requirements, or the remote connection settings are not in accordance with the requirements, this is a finding."
  desc 'fix', 'Configure the application server to enforce remote connection settings.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4902r282993_chk'
  tag severity: 'medium'
  tag gid: 'V-204782'
  tag rid: 'SV-204782r508029_rule'
  tag stig_id: 'SRG-APP-000315-AS-000094'
  tag gtitle: 'SRG-APP-000315'
  tag fix_id: 'F-4902r282994_fix'
  tag 'documentable'
  tag legacy: ['SV-71685', 'V-57413']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
