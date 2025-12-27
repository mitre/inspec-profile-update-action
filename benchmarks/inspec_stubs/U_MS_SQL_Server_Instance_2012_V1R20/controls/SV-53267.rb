control 'SV-53267' do
  title 'SQL Server must protect the integrity of publicly available information and SQL Servers configuration from unauthorized Server Roles access.'
  desc 'The purpose of this control is to ensure organizations explicitly address the protection needs for public information and applications, with such protection likely being implemented as part of other security controls. If SQL Server contains publicly available information, though not concerned with confidentiality, SQL Server must maintain the integrity of the data. If data available to the public is not protected from unauthorized modification or deletion, then the data cannot be trusted by those accessing it.

The user account associated with public access must not have access to the OS or SQL Server configuration information, include read access to schema information.

This requirement is not intended to prevent the establishment of public-facing systems for the purpose of collecting data from the public.'
  desc 'check', "If SQL Server is not housing or distributing publicly available information, this finding is NA.

Obtain from the DBA or system documentation the list of publicly available data within SQL Server and the role names that assign read-only access to that public data.

Obtain the publicly available user account name being used to access SQL Server.

Navigate to Start >> Administrative Tools >> Server Manager >> Server Manager (<'server name'>) >> Configuration >> Local Users and Groups >> Groups >> right click 'Guests' >> Properties >> 'Members:'
The publicly available user account will likely be in the OS 'Guests' group.

Determine if SQL Server is granting more than read access to the publicly available information through SQL Server 'Server Roles'.

Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'user account'> >> Properties >> Server Roles.

If any 'Server Roles' are marked that grant more than read access to the publicly available information, this is a finding."
  desc 'fix', "Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Logins >> right click <'user account'> >> Properties >> Server Roles.

Uncheck the 'Server Roles' that are checked and grant more than read-only access to the publicly available information."
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47568r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40913'
  tag rid: 'SV-53267r3_rule'
  tag stig_id: 'SQL2-00-020300'
  tag gtitle: 'SRG-APP-000201-DB-000145'
  tag fix_id: 'F-46195r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
