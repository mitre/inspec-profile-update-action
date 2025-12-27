control 'SV-250626' do
  title 'The system must enable lockdown mode to restrict remote access.'
  desc 'Enabling lockdown prevents all API-based access by the accounts to the ESXi host. Enabling lockdown mode disables all remote access to ESXi machines. 

There are some operations, such as backup and troubleshooting that require direct access to the host. In these cases Lockdown Mode can be disabled on a temporary basis for specific hosts as needed, and then re-enabled when the task is completed. Lockdown restricts access to the ESXi console to the root user only, requiring non-root users access the host through vSphere Client/vCenter where RBAC and logging can be used to restrict and log activity. By forcing all interaction to occur through vCenter Server, the risk of someone inadvertently attaining elevated privileges or performing tasks that are not properly audited is greatly reduced. 

Note:  Lockdown mode does not apply to root users who log in using authorized keys. When an authorized key file is used for root user authentication, root users are not prevented from accessing a host with SSH even when the host is in lockdown mode. Use of an authorized key file for root must therefore be disallowed.'
  desc 'check', 'For ESXi hosts that are not managed by a vCenter Server, this check is not applicable.

From the vSphere client, select the host then select "Configuration >> Security Profile". Verify Lockdown Mode is enabled. 

Alternatively, issue the following command via the CLI:
# vim-cmd vimsvc/auth/lockdown_is_enabled

If Lockdown Mode is not enabled (true), this is a finding.'
  desc 'fix', 'To enable Lockdown mode on an ESXi host managed by a vCenter Server, log in directly the ESXi host as root. Open the DCUI on the host. Press F2 for Initial Setup. Toggle the Configure Lockdown Mode setting and configure Lockdown Mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54061r798875_chk'
  tag severity: 'medium'
  tag gid: 'V-250626'
  tag rid: 'SV-250626r798877_rule'
  tag stig_id: 'SRG-OS-000092-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54015r798876_fix'
  tag 'documentable'
  tag legacy: ['SV-51243', 'V-39385']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
