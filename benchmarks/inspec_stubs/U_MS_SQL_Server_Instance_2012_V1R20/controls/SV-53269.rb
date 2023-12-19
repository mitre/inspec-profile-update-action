control 'SV-53269' do
  title 'SQL Server must protect the integrity of publicly available information and applications.'
  desc "The purpose of this control is to ensure organizations explicitly address the protection needs for public information and applications, with such protection likely being implemented as part of other security controls. If SQL Server contains publicly available information, though not concerned with confidentiality, SQL Server OS must maintain the integrity of the data. If data available to the public is not protected from unauthorized modification or deletion, then the data cannot be trusted by those accessing it.

The user account associated with public access must not have access to the OS configuration information. Determine what publicly available user account is being used to access SQL Server and validate that the publicly available user account only has read access to the public data and nothing else.

The OS level 'Guests' role grants connection access to the server without granting any other privileges. SQL Server configuration settings are used to grant access to the publicly available information, but this control ensures that the OS only is granted connection access to the server.

This requirement is not intended to prevent the establishment of public-facing systems for the purpose of collecting data from the public."
  desc 'check', "If SQL Server is not housing or distributing publicly available information, this finding is NA.

If SQL Server supports an application collecting information from the public, this is NA.

Obtain the publicly available user account name being used to access SQL Server.

Using an account with System Administrator privileges, from a command prompt, type lusrmgr.msc, and press [ENTER].
Navigate to Groups >> right click 'Guests' >> Properties >> 'Members:'
The publicly available user account will be in the OS 'Guests' group, or another explicitly defined group.

Determine if the obtained publicly available user account is located in any other groups.

In lusrmgr.msc, navigate to Users. Right click publicly available account name. Click Properties, then click the 'Member of' tab.

If the publicly available user account is found in any group 'Members' listing other than 'Guests', this is a finding.

In SQL, for the account that is used for public access, ensure that read-only access is the only access granted. If any other access is granted, this is a finding."
  desc 'fix', "Using an account with System Administrator privileges, from a command prompt, type lusrmgr.msc, and press [ENTER].
Navigate to Groups.

Locate the additional group(s) from which the publicly available user account must be removed.

Right click <'the group to modify' >> Properties >> 'Members:'

Remove the publicly available user account from the group by clicking/highlighting the account and then clicking the 'Remove' button.

Revoke any update permissions for a guest being used in the context of a guest account."
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47570r3_chk'
  tag severity: 'medium'
  tag gid: 'V-40915'
  tag rid: 'SV-53269r3_rule'
  tag stig_id: 'SQL2-00-020100'
  tag gtitle: 'SRG-APP-000201-DB-000145'
  tag fix_id: 'F-46197r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
