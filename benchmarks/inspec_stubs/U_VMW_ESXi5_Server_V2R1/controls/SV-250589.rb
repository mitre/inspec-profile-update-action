control 'SV-250589' do
  title 'The system must only use remote syslog servers (log hosts) justified and documented using site-defined procedures.'
  desc "If a remote log host is in use and it has not been justified and documented with the IAO, sensitive information could be obtained by unauthorized users without the SA's knowledge. A remote log host is any host to which the system is sending syslog messages over a network."
  desc 'check', %q(Verify that the vSphere Syslog Collector syslog host has been justified and documented with the IAO. From the vSphere Client:  
Select the host and click "Configuration >> Advanced Settings >> Syslog >>  Global". 
Verify that the 'Syslog.global.logHost' is set to the (site-specific) syslog server hostname. 

If the 'Syslog.global.logHost' is not justified and documented with the IAO, this is a finding.)
  desc 'fix', %q(Step 1:  Verify that the vSphere Syslog Collector syslog host has been configured. If not, install/enable the vSphere Syslog Collector. Step 2:  From the vSphere Client:  Select the host and click "Configuration >> Advanced Settings >> Syslog >> Global". Step 3: Set 'Syslog.global.logHost' to the syslog server hostname justified and documented with the IAO.)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54024r798764_chk'
  tag severity: 'medium'
  tag gid: 'V-250589'
  tag rid: 'SV-250589r798766_rule'
  tag stig_id: 'GEN005460-ESXI5-000060'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53978r798765_fix'
  tag 'documentable'
  tag legacy: ['V-39278', 'SV-51094']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
