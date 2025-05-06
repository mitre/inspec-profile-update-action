control 'SV-250655' do
  title 'The system must disable ESXi Shell unless needed for diagnostics or troubleshooting.'
  desc 'The ESXi Shell is an interactive command line environment available locally from the DCUI or remotely via SSH. Activities performed from the ESXi Shell bypass vCenter RBAC and audit controls. The ESXi shell should only be turned on when needed to troubleshoot/resolve problems that cannot be fixed through the vSphere client.'
  desc 'check', 'From the vSphere Client, select the host then select "Configuration >> Security Profiles". In the Services section select "Properties". Select the "ESXi Shell" and click Options. Verify the ESXi Shell is set to "Start and stop manually".

If the ESXi Shell service startup policy is not set to "Start and stop manually", this is a finding.'
  desc 'fix', 'From the vSphere Client, select the host then select "Configuration >>  Security Profiles". In the Services section select "Properties". Select the "ESXi Shell" and click Options. Stop the ESXi Shell and select the option to "Start and stop manually".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54090r798962_chk'
  tag severity: 'medium'
  tag gid: 'V-250655'
  tag rid: 'SV-250655r798964_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000136'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54044r798963_fix'
  tag 'documentable'
  tag legacy: ['V-39295', 'SV-51111']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
