control 'SV-76921' do
  title 'The ColdFusion Root Administrator account must have a unique username.'
  desc 'The ColdFusion Root Administrator account is an administrative account setup during the installation process.  This account has privileges to view, update and delete data within the entire ColdFusion Administrator Console.  The account is meant to be used to setup ColdFusion after installation, but should only be used in emergency situations once user accounts are created.  The account is similar to the Administrator account in Windows or the root account in Linux.

To help protect the account, the account username should not be admin or administrator.  If setup with these usernames, an attacker already knows 50% of the information needed to gain access.  A unique and not easily guessable username must be used to hinder the discovery of the account credentials.'
  desc 'check', %q(Locate the neo-security.xml file and locate the Root Administrator username.

For ColdFusion running on Windows:
1. Open the neo-security.xml in notepad.exe (Hint: Turn Word Wrap on to make the file easier to read.).
2. Under the menu "Edit", select the "Find…" menu item.
3. In the "Find" window, put in the search text 'admin.userid.root'> including the single quotes.
4. The Root Administrator username follows this tag between the <string> and </string> tags.  A sample entry may look like this if the Root Administrator username were Administrator:  <var name='admin.userid.root'><string>Administrator</string>

For ColdFusion running on Linux:
1. Change to the directory where the neo-security.xml file is located.
2. Execute the following command to return the Root Administrator username: 
     cat neo-security.xml | grep –i –oP ‘admin.userid.root’+”’><string>\K\w+”

If the Root Administrator username is any upper-and lower-case mix of characters for the words admin or administrator (e.g., admin, Admin, ADMIN, Administrator, ADMINISTRATOR, etc.), this is a finding.)
  desc 'fix', %q(Locate the neo-security.xml file and change to the directory where the file is located. 

Note: Make a backup of the file before making any modifications.

For ColdFusion running on Windows:
1. Open the file neo-security.xml in notepad.exe (Hint: Turn Word Wrap on to make the file easier to read.).
2. Under the menu "Edit", select the "Find…" menu item.
3. In the "Find" window, put in the search text 'admin.userid.root'> including the single quotes.
4. The Root Administrator username follows this tag between the <string> and </string>  tags.  A sample entry may look like this if the Root Administrator username were Administrator:  <var name='admin.userid.root'><string>Administrator</string>
5. Update the Root Administrator username.  The new Root Administrator username must not be any upper and lower case mix of characters for the words admin or administrator, e.g., admin, Admin, ADMIN, Administrator, ADMINISTRATOR, etc.
6. Save the file.
7. Restart ColdFusion to have the new username take effect.  Within a terminal window, change to the bin directory under the ColdFusion installation directory and execute the command:
     coldfusion -restart -console

ColdFusion running on Linux:
1. Change to the directory where the neo-security.xml file is located.
2. Update the Root Administrator username by editing the neo-security.xml file.
3. Locate the <var name='admin.userid.root'> tag.  The username is located in between the <string> and </string> tags that follow.  A sample entry may look like this if the Root Administrator username were Administrator:  <var name='admin.userid.root'><string>Administrator</string>
4. Update the Root Administrator username.  The new Root Administrator username must not be any upper and lower case mix of characters for the words admin or administrator, e.g., admin, Admin, ADMIN, Administrator, ADMINISTRATOR, etc.
5. Save the file.
6. Restart ColdFusion to have the new username take effect.  ColdFusion can be restarted by changing to the bin directory under the ColdFusion installation directory and execute the command:
     coldfusion restart

Validate that the new username is being used and that the system is operating properly.  Once validated, the backup neo-security.xml file must be deleted.)
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63235r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62431'
  tag rid: 'SV-76921r1_rule'
  tag stig_id: 'CF11-03-000110'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-68351r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
