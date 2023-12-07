control 'SV-78471' do
  title 'The vCenter Server services must be ran using a service account instead of a built-in Windows account.'
  desc 'You can use the Microsoft Windows built-in system account or a domain user account to run vCenter Server.  The Microsoft Windows built-in system account has more permissions and rights on the server than the vCenter Server system requires, which can contribute to security problems. With a domain user account, you can enable Windows authentication for SQL Server; it also allows more granular security and logging. The installing account only needs to be a member of the Administrators group, and have permission to act as part of the operating system and log on as a service. If you are using SQL Server for the vCenter database, you must configure the SQL Server database to allow the domain account access to SQL Server.'
  desc 'check', 'This control only applies to Windows based vCenter installations.

The following services should be set to run as a service account:

VMware Content Library Service
VMware Inventory Service
VMware Performance Charts
VMware VirtualCenter Server

vCenter should be installed using the service account as that will configure the services appropriately.

If vCenter is not installed with a service account and the services identified in this control and not running as a service account, this is a finding.'
  desc 'fix', 'For each of the following services open the services console on the vCenter server and right click and select properties on the service.  Go to the Log On tab and configure the service to run as a service account and restart the service.

VMware Content Library Service
VMware Inventory Service
VMware Performance Charts
VMware VirtualCenter Server'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64733r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63981'
  tag rid: 'SV-78471r1_rule'
  tag stig_id: 'VCWN-06-000022'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69911r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
