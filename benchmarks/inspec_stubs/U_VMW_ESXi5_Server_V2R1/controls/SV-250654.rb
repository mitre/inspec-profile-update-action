control 'SV-250654' do
  title 'The system must disable DCUI to prevent local administrative control.'
  desc 'The DCUI allows for low-level host configuration, such as configuring IP address, hostname, and root password, as well as diagnostic capabilities, such as enabling the ESXi shell, viewing log files, restarting agents, and resetting configurations. Actions performed from the DCUI are not tracked by vCenter Server. Even if Lockdown Mode is enabled, someone with the root password can perform administrative tasks in the DCUI bypassing RBAC and auditing controls provided through vCenter. DCUI access can be disabled. Disabling it prevents all local activity and thus forces actions to be performed in vCenter Server where they can be centrally audited and monitored.'
  desc 'check', 'From the vSphere Client, select the host and select "Configuration >> Security Profile". In the services section select "Properties". Select "Direct Console UI" and click "Options". From the pop-up verify the DCUI service startup policy is set to "start and stop manually".

If the DCUI service startup policy is not set to "Start and stop manually", this is a finding.'
  desc 'fix', 'From the vSphere Client, select the host and select "Configuration >> Security Profile". In the services section select "Properties". Select "Direct Console UI" and click "Options". From the pop-up stop the DCUI service and set the startup policy to "start and stop manually".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54089r798959_chk'
  tag severity: 'medium'
  tag gid: 'V-250654'
  tag rid: 'SV-250654r798961_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000135'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54043r798960_fix'
  tag 'documentable'
  tag legacy: ['SV-51110', 'V-39294']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
