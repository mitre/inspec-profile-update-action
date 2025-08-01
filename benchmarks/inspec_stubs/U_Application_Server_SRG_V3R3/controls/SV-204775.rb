control 'SV-204775' do
  title 'The application server must restrict error messages only to authorized users.'
  desc "If the application provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

Application servers must protect the error messages that are created by the application server. All application server users' accounts are used for the management of the server and the applications residing on the application server. All accounts are assigned to a certain role with corresponding access rights. The application server must restrict access to error messages so only authorized users may view them. Error messages are usually written to logs contained on the file system. The application server will usually create new log files as needed and must take steps to ensure that the proper file permissions are utilized when the log files are created."
  desc 'check', 'Review the application server configuration and documentation to determine if the application server will restrict access to error messages so only authorized users may view or otherwise access them.

If the application server cannot be configured to restrict access to error messages to only authorized users, this is a finding.'
  desc 'fix', 'Configure the application server to restrict access to error messages so only authorized users may view or otherwise access them.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4895r282972_chk'
  tag severity: 'medium'
  tag gid: 'V-204775'
  tag rid: 'SV-204775r508029_rule'
  tag stig_id: 'SRG-APP-000267-AS-000170'
  tag gtitle: 'SRG-APP-000267'
  tag fix_id: 'F-4895r282973_fix'
  tag 'documentable'
  tag legacy: ['SV-46728', 'V-35441']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
