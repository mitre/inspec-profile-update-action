control 'SV-222626' do
  title 'The designer must ensure the application does not store configuration and control files in the same directory as user data.'
  desc 'Application configuration settings and user data are required to be stored in separate locations in order to prevent application users from possibly being able to access application configuration settings or application data files. Without proper access controls and separation of application configuration settings from user data, there is the potential that existing code or configuration settings could be changed by users. These changes in code can lead to a Denial of Service (DoS) attack or allow malicious code to be placed within the application. In addition, collocating application data and code complicates many issues such as backup, recovery, directory access privilege, and upgrades.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Ask the application administrator or examine the application documentation to determine the file location of the application configuration settings and user data.

Identify the directory where the application code, configuration settings and other application control data are located.

Identify where user data is stored.

Examine file permissions to application folder.

If the application user data is located in the same directory as the application configuration settings or control files, or if the file permissions allow application users write access to application configuration settings, this is a finding.'
  desc 'fix', 'Separate the application user data into a different directory than the application code and user file permissions to restrict user access to application configuration settings.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24296r493786_chk'
  tag severity: 'medium'
  tag gid: 'V-222626'
  tag rid: 'SV-222626r508029_rule'
  tag stig_id: 'APSC-DV-002960'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24285r493787_fix'
  tag 'documentable'
  tag legacy: ['SV-84931', 'V-70309']
  tag cci: ['CCI-000345', 'CCI-000366']
  tag nist: ['CM-5', 'CM-6 b']
end
