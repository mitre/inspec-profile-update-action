control 'SV-235958' do
  title 'Oracle WebLogic must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. 

It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized modification. If an attacker were to modify audit tools, he could also manipulate logs to hide evidence of malicious activity. 

Application servers provide a web- and/or a command line-based management functionality for managing the application server audit capabilities. In addition, subsets of audit tool components may be stored on the file system as jar or xml configuration files. The application server must ensure that in addition to protecting any web-based audit tools, any file system-based tools are protected as well.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have audit tool configuration access
6. From users settings page, select 'Groups' tab
7. Ensure the 'Chosen' table does not contain the role - 'Admin'
8. Repeat steps 5-7 for all users that must not have audit tool configuration access

If any users that should not have access to the audit tools contains the role of 'Admin', this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Users and Groups' tab -> 'Users' tab
5. From 'Users' table, select a user that must not have audit tool configuration access
6. From users settings page, select 'Groups' tab
7. From the 'Chosen' table, use the shuttle buttons to remove the role - 'Admin'
8. Click 'Save'
9. Repeat steps 5-8 for all users that must not have audit tool configuration access"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39177r628650_chk'
  tag severity: 'medium'
  tag gid: 'V-235958'
  tag rid: 'SV-235958r628652_rule'
  tag stig_id: 'WBLC-02-000099'
  tag gtitle: 'SRG-APP-000122-AS-000082'
  tag fix_id: 'F-39140r628651_fix'
  tag 'documentable'
  tag legacy: ['SV-70519', 'V-56265']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
