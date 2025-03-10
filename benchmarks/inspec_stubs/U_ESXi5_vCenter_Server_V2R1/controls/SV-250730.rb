control 'SV-250730' do
  title 'The vCenter Server must be installed using a service account instead of a built-in Windows account.'
  desc 'The Microsoft Windows built-in system account or a user account can be used to run vCenter Server. With a user account, the Windows authentication for SQL Server can be enabled; it also provides more security. The user account must be an administrator on the local machine. In the installation wizard, specify the account name as DomainName\\Username. If using SQL Server for the vCenter database, the SQL Server database must be configured to allow the domain account access to SQL Server. The Microsoft Windows built-in system account has more permissions and rights on the server than the vCenter Server system requires, which can contribute to security problems. A local user, administrative level account with limited permissions and rights must be set up for the vCenter Server system.'
  desc 'check', 'Verify vCenter Server was installed using a special-purpose user account on the Windows host with a local-only administrator role. This account should have the "Act as part of the operating system" privilege, and write access to the local file system with a local-only administrator role.

If the vCenter Server was not installed with a special-purpose, local-only administrator role with the "Act as part of the operating system" privilege, this is a finding.'
  desc 'fix', 'Re-install the vCenter Server with a special-purpose, local-only administrator role with the "Act as part of the operating system" privilege.'
  impact 0.3
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54165r799878_chk'
  tag severity: 'low'
  tag gid: 'V-250730'
  tag rid: 'SV-250730r799880_rule'
  tag stig_id: 'VCENTER-000008'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54119r799879_fix'
  tag 'documentable'
  tag legacy: ['SV-51406', 'V-39548']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
