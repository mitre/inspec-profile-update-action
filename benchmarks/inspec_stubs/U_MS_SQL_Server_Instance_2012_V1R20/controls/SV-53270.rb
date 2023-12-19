control 'SV-53270' do
  title 'SQL Server must protect the integrity of publicly available information and SQL Servers configuration from unauthorized Securables access.'
  desc "The purpose of this control is to ensure organizations explicitly address the protection needs for public information and applications, with such protection likely being implemented as part of other security controls.

SQL Server must be configured to contain publicly available information. Though not concerned with confidentiality, SQL Server must maintain the integrity of the data. If data available to the public is not protected from unauthorized modification or deletion, then the data cannot be trusted by those accessing it. A publicly available user account must not have access to the OS or SQL Server configuration information, including read access to schema information. Determine what publicly available user account is being used to access SQL Server and validate that the publicly available user account only has read access to the public data and nothing else. This read-only access does not include SQL Server 'Securables' assignments.

SQL Server 'Securables' assignments grant the assignee privileges that are beyond read access to data. No public user account must have SQL Server 'Securables' privileges. Any assigned 'Securables' privileges to the public user account must be removed.

Likely the only 'Server roles' assignment for the publicly available user account would be 'public'. The only other 'Server roles' that could be authorized as read-only is a user-defined 'Server role'. It is more likely that read-only access is set up at the user database instance in role(s) specifically set up for this purpose. Assignment to the user database instances are made in the 'User Mapping' highlight within a user's properties.

This requirement is not intended to prevent the establishment of public-facing systems for the purpose of collecting data from the public."
  desc 'check', "If SQL Server is not housing or distributing publicly available information, this finding is NA.

If SQL Server supports an application collecting information from the public, this is NA.

Obtain from the DBA or system documentation the list of publicly available data within SQL Server.
Obtain the publicly available user account(s) being used to access SQL Server. 

Determine if SQL Server is granting more than read access to the publicly available information through SQL Server 'Securables'.

Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'user account'> >> Properties >> Securables.

If any 'Securables' are listed, this is a finding."
  desc 'fix', "Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'user account'> >> Properties >> Securables >> highlight 'Securable Name'.

Uncheck all 'Grant', 'With Grant', and 'Deny' for the highlighted 'Securable'."
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47571r3_chk'
  tag severity: 'medium'
  tag gid: 'V-40916'
  tag rid: 'SV-53270r3_rule'
  tag stig_id: 'SQL2-00-020000'
  tag gtitle: 'SRG-APP-000201-DB-000145'
  tag fix_id: 'F-46198r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
