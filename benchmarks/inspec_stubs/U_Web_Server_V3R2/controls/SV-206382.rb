control 'SV-206382' do
  title 'The web server must have resource mappings set to disable the serving of certain file types.'
  desc 'Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client.

By not specifying which files can and which files cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc. 

The web server must only allow hosted application file types to be served to a user and all other types must be disabled.'
  desc 'check', 'Review the web server documentation and deployment configuration to determine what types of files are being used for the hosted applications.

If the web server is configured to allow other file types not associated with the hosted application, especially those associated with logs, configuration files, passwords, etc., this is a finding.'
  desc 'fix', 'Configure the web server to only serve file types to the user that are needed by the hosted applications.  All other file types must be disabled.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6643r377738_chk'
  tag severity: 'medium'
  tag gid: 'V-206382'
  tag rid: 'SV-206382r879587_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000083'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6643r377739_fix'
  tag 'documentable'
  tag legacy: ['SV-54278', 'V-41701']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
