control 'SV-250647' do
  title 'The operating system must protect the audit records resulting from non-local accesses to privileged accounts and the execution of privileged functions.'
  desc 'Remote logging to a central log host provides a secure, centralized store for ESXi logs. By gathering host log files onto a central host it can more easily monitor all hosts with a single tool. It can also do aggregate analysis and searching to look for such things as coordinated attacks on multiple hosts. Logging to a secure, centralized log server also helps prevent log tampering and also provides a long-term audit record.'
  desc 'check', %q(Verify the vSphere Syslog Collector syslog host has been configured. From the vSphere Client:  Select the host and click "Configuration >> Advanced Settings >> Syslog >> Global". Verify the 'Syslog.global.logHost' is set to the (site-specific) syslog server hostname.

If the 'Syslog.global.logHost' is unconfigured, this is a finding.)
  desc 'fix', %q(Step 1:  Verify the vSphere Syslog Collector syslog host has been configured. If not, install/enable the vSphere Syslog Collector.
Step 2:  From the vSphere Client:  Select the host and click "Configuration >> Advanced Settings >> Syslog >> Global".  
Step 3: Set 'Syslog.global.logHost' to the syslog server hostname.)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54082r798938_chk'
  tag severity: 'medium'
  tag gid: 'V-250647'
  tag rid: 'SV-250647r798940_rule'
  tag stig_id: 'SRG-OS-000217-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54036r798939_fix'
  tag 'documentable'
  tag legacy: ['V-39410', 'SV-51268']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
