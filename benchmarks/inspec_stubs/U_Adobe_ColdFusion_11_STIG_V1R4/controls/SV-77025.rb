control 'SV-77025' do
  title 'The ColdFusion error messages must be restricted to only authorized users.'
  desc "If the application provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

Application servers must protect the error messages that are created by the application server. All application server users' accounts are used for the management of the server and the applications residing on the application server. All accounts are assigned to a certain role with corresponding access rights. The application server must restrict access to error messages so only authorized users may view them. Error messages are usually written to logs contained on the file system. The application server will usually create new log files as needed and must take steps to ensure that the proper file permissions are utilized when the log files are created."
  desc 'check', 'Within the Administrator Console, navigate to the "User Manager" page under the "Security" menu.  Review each defined user and ask the SA if the user should have access to read error messages.  For each user that should not be able to read error messages, review the roles assigned to the user account.

If any user has the Debugging and Logging>Logging role that should not be able to read error messages, this is a finding.'
  desc 'fix', 'Navigate to the "User Manager" page under the "Security" menu.  Remove the "Debugging and Logging>Logging" role from each user that should not have access to read error messages.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63339r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62535'
  tag rid: 'SV-77025r1_rule'
  tag stig_id: 'CF11-06-000222'
  tag gtitle: 'SRG-APP-000267-AS-000170'
  tag fix_id: 'F-68455r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
