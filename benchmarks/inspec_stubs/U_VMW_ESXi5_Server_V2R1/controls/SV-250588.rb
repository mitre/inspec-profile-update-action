control 'SV-250588' do
  title 'The system must not be used as a syslog server (log host) for systems external to the enclave.'
  desc 'Syslog messages are typically unencrypted and may contain sensitive information and are, therefore, restricted to the enclave.'
  desc 'check', %q(Verify that the vSphere Syslog Collector syslog host has been justified and documented with the IAO.
From the vSphere Client:  Select the host and click "Configuration >> Advanced Settings >> Syslog >> Global".  
Verify that the 'Syslog.global.logHost' is set to the (site-specific) syslog server hostname.

If the 'Syslog.global.logHost' is not restricted to the enclave, this is a finding.)
  desc 'fix', %q(Step 1:  Verify that the vSphere Syslog Collector syslog host has been configured. If not, install/enable the vSphere Syslog Collector.
Step 2:  From the vSphere Client:  Select the host and click "Configuration >> Advanced Settings >> Syslog >> Global".  
Step 3: Set 'Syslog.global.logHost' to the syslog server hostname restricted to the enclave.)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54023r798761_chk'
  tag severity: 'medium'
  tag gid: 'V-250588'
  tag rid: 'SV-250588r798763_rule'
  tag stig_id: 'GEN005440-ESXI5-000078'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53977r798762_fix'
  tag 'documentable'
  tag legacy: ['SV-51095', 'V-39279']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
