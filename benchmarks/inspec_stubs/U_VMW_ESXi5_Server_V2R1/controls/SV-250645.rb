control 'SV-250645' do
  title 'Remote logging for ESXi hosts must be configured.'
  desc 'Remote logging to a central log host provides a secure, centralized store for ESXi logs. By gathering host log files onto a central host it can more easily monitor all hosts with a single tool. It can also do aggregate analysis and searching to look for such things as coordinated attacks on multiple hosts. Logging to a secure, centralized log server also helps prevent log tampering and also provides a long-term audit record.'
  desc 'check', %q(Verify the vSphere Syslog Collector syslog host has been configured. From the vSphere Client:  Select the host and click "Configuration >> Advanced Settings >> Syslog >> Global". Verify the 'Syslog.global.logHost' is set to the (site-specific) syslog server hostname.

If the 'Syslog.global.logHost' is unconfigured, this is a finding.)
  desc 'fix', %q(Step 1:  Verify the vSphere Syslog Collector syslog host has been configured. If not, install/enable the vSphere Syslog Collector.
Step 2:  From the vSphere Client:  Select the host and click "Configuration >> Advanced Settings >> Syslog >> Global".  
Step 3: Set 'Syslog.global.logHost' to the syslog server hostname.)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54080r798932_chk'
  tag severity: 'medium'
  tag gid: 'V-250645'
  tag rid: 'SV-250645r798934_rule'
  tag stig_id: 'SRG-OS-000197-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54034r798933_fix'
  tag 'documentable'
  tag legacy: ['V-39408', 'SV-51266']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
