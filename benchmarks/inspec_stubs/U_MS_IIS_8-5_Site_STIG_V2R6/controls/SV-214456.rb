control 'SV-214456' do
  title 'The IIS 8.5 website must have resource mappings set to disable the serving of certain file types.'
  desc 'Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client.

By not specifying which files can and which files cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc.

The web server must only allow hosted application file types to be served to a user and all other types must be disabled.'
  desc 'check', 'For Request Filtering, the ISSO must document and approve all allowable scripts the website allows (white list) and denies (black list). The white list and black list will be compared to the Request Filtering in IIS 8.5. Request Filtering at the site level take precedence over Request Filtering at the server level.

Follow the procedures below for each site hosted on the IIS 8.5 web server: 

Open the IIS 8.5 Manager.
Click the site name to review.
Double-click Request Filtering >> File Name Extensions Tab.

If any script file extensions from the black list are not denied, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server: 

Open the IIS 8.5 Manager.
Click the site name to review.
Double-click Request Filtering >> File Name Extensions Tab >> Deny File Name Extension.
Add any script file extensions listed on the black list that are not listed.
Select "Apply" from the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15665r505306_chk'
  tag severity: 'medium'
  tag gid: 'V-214456'
  tag rid: 'SV-214456r508659_rule'
  tag stig_id: 'IISW-SI-000216'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag fix_id: 'F-15663r505307_fix'
  tag 'documentable'
  tag legacy: ['SV-91497', 'V-76801']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
