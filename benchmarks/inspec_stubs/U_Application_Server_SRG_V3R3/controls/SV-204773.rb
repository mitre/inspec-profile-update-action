control 'SV-204773' do
  title 'The application server must identify potentially security-relevant error conditions.'
  desc 'The structure and content of error messages need to be carefully considered by the organization and development team.  Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system.  The extent to which the application server is able to identify and handle error conditions is guided by organizational policy and operational requirements. Adequate logging levels and system performance capabilities need to be balanced with data protection requirements.

The structure and content of error messages needs to be carefully considered by the organization and development team.

Application servers must have the capability to log at various levels which can provide log entries for potential security-related error events.

An example is the capability for the application server to assign a criticality level to a failed logon attempt error message, a security-related error message being of a higher criticality.'
  desc 'check', 'Review the application server configuration to determine if the system identifies potentially security-relevant error conditions on the server.

If this function is not performed, this is a finding.'
  desc 'fix', 'Configure the application server to identify potentially security-relevant error conditions on the server.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4893r282966_chk'
  tag severity: 'medium'
  tag gid: 'V-204773'
  tag rid: 'SV-204773r508029_rule'
  tag stig_id: 'SRG-APP-000266-AS-000168'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-4893r282967_fix'
  tag 'documentable'
  tag legacy: ['SV-71843', 'V-57567']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
