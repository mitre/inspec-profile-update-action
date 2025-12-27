control 'SV-108703' do
  title 'The default mysql_secure_installation must be installed.'
  desc 'The mysql_secure_installation configuration of MySQL adds several important configuration settings that block several attack vectors. The My SQL application could be exploited by an adversary without mysql_secure_installation.

SFR ID: FMT_SMF.1(2)b. / CM-7(1)(b)

'
  desc 'check', 'Verify the mysql_secure_installation has been installed on the Jamf host server. 

1. Log in to MySQL. Execute the "show databases;" command.
- Verify that the database named "Test" is not shown in output of the command.

2. Verify the root account has a string representing the password and not a blank value.
- select * from mysql.user;

3. Verify the anonymous users have been removed and verify the user field contains a user name.
- select * from mysql.user;

All three steps must be correct to indicate mysql_secure_installation has been executed.

If the mysql_secure_installation has not been installed on the Jamf host server, this is a finding.'
  desc 'fix', 'Install the mysql_secure_installation. 

1. Install MySQL.
2. Using the Jamf Pro Security Recommendations document, go to the path based on the host operating system and execute the appropriate mysql_secure_installation script.'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98449r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99599'
  tag rid: 'SV-108703r1_rule'
  tag stig_id: 'JAMF-10-100060'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105283r1_fix'
  tag satisfies: ['SRG-APP-000383']
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
