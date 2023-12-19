control 'SV-250657' do
  title 'The system must disable SSH.'
  desc 'The ESXi Shell is an interactive command line interface (CLI) available at the ESXi server console. The ESXi shell provides temporary access to commands essential for server maintenance. Intended primarily for use in break-fix scenarios, the ESXi shell is well suited for checking and modifying configuration details, not always generally accessible, using the vSphere Client. The ESXi shell is accessible remotely using SSH. Under normal operating conditions, SSH access to the host must be disabled. As with the ESXi shell, SSH is also intended only for temporary use during break-fix scenarios. SSH must therefore be disabled under normal operating conditions and must only be enabled for diagnostics or troubleshooting. Remote access to the host must therefore be limited to the vSphere Client at all other times.'
  desc 'check', %q(From the vSphere client, select the ESXi host, go to "Configuration >> Security Profile". In the "Services" section select "Properties".  Verify 'SSH' is stopped.

If the SSH service is running, this is a finding.)
  desc 'fix', %q(From the vSphere client, select the ESXi host, go to "Configuration >> Security Profile". In the "Services" section select "Properties". Select "SSH", "Options..." and configure the 'SSH' option to "Start and stop manually".)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54092r798968_chk'
  tag severity: 'medium'
  tag gid: 'V-250657'
  tag rid: 'SV-250657r798970_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000138'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54046r798969_fix'
  tag 'documentable'
  tag legacy: ['V-39390', 'SV-51248']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
