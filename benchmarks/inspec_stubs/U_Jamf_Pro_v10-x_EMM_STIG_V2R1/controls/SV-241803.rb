control 'SV-241803' do
  title 'The MySQL DatabasePassword key must be removed or set to a blank value in the database configuration file in Jamf Pro EMM.'
  desc 'If the database password is not removed or set to a blank value in the configuration file, the user is not forced to enter the password, which would allow an adversary to access to access the database.

SFR ID: FMT_SMF.1(2)b. / CM-5(10)

'
  desc 'check', 'Verify the MySQL <DatabasePassword> key has been removed or set to a blank value in Jamf Pro EMM.

1. On the Jamf Pro server, navigate to the JSS/Tomcat/webapps/ROOT/WEB-INF/xml.
2. Find the "Database.xml" file and open it in a text editor.
3. Find the <DatabasePassword>.
4. Verify that there is no password.

If the MySQL <DatabasePassword> key has not been removed or not set to a blank value, this is a finding.'
  desc 'fix', 'Remove the MySQL <DatabasePassword> key or set to a blank value in Jamf Pro EMM.

If the database password is removed from the configuration file, the database password must be entered manually for the Jamf Pro EMM server web app during startup. In a clustered environment, the database password must be entered manually for each individual node.

Note: Default values are included below for reference only. Use unique values in production environments.

<Database>
...
<DatabaseName>jamfsoftware</DatabaseName>
<DatabaseUser>jamfsoftware</DatabaseUser>
<DatabasePassword></DatabasePassword>
...
</Database>'
  impact 0.5
  ref 'DPMS Target Jamf Pro v10-x EMM'
  tag check_id: 'C-45079r685161_chk'
  tag severity: 'medium'
  tag gid: 'V-241803'
  tag rid: 'SV-241803r879887_rule'
  tag stig_id: 'JAMF-10-100120'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-45038r685162_fix'
  tag satisfies: ['SRG-APP-000380']
  tag 'documentable'
  tag legacy: ['SV-108711', 'V-99607']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
