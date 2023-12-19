control 'SV-30021' do
  title 'The manufacturer’s default passwords must be changed for all Hardware Management Console   (HMC) Management software.'
  desc 'The changing of passwords from the HMC default values, blocks malicious users with knowledge of these default passwords, from creating a denial of service or  from reconfiguring the HMC topology leading to a compromise of sensitive data. The system administrator will ensure that the manufacturer’s default passwords are changed for all HMC management software.'
  desc 'check', 'Have the System Administrator logon to the HMC and validate that all default passwords have been changed.

Go to task Modify User, select user, select Modify and enter and confirm new password. 

User ID		Default Password
•	OPERATOR		PASSWORD
•	ADVANCED		PASSWORD
•	SYSPROG		PASSWORD
•	ACSADMIN		PASSWORD

The System Administrator is to validate that each user has his/her own user ID and password and that sharing of user-IDs and passwords is not permitted.

Default user IDs and passwords are established as part of a base HMC. The System Administrator must assign new user IDs and passwords for each user and remove the default user IDs as soon as the HMC is installed by using the User Profiles task or the Manage Users Wizard.   

If all the default passwords have not been changed, and each user is not assigned a separate user ID and password, then this is a FINDING'
  desc 'fix', 'The System Administrator must logon to the HMC and validate that all Default Passwords have been changed.
	
User ID		Default Password
OPERATOR		PASSWORD
ADVANCED		PASSWORD
SYSPROG		PASSWORD
ACSADMIN		PASSWORD

Default user IDs and passwords are established as part of a base HMC. The System Administrator must assign new user IDs and passwords for each user and remove the default user IDs as soon as the HMC is installed by using the User Profiles task or the Manage Users Wizard.

Go to task Modify User, select user, select Modify and enter and confirm new password.'
  impact 0.7
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29874r1_chk'
  tag severity: 'high'
  tag gid: 'V-24353'
  tag rid: 'SV-30021r2_rule'
  tag stig_id: 'HMC0080'
  tag gtitle: 'HMC0080'
  tag fix_id: 'F-26761r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager', 'Systems Programmer']
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-001989']
  tag nist: ['IA-5 e']
end
