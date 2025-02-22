control 'SV-250646' do
  title 'The operating system must back up audit records on an organization-defined frequency onto a different system or media than the system being audited.'
  desc 'Remote logging to a central log host provides a secure, centralized store for ESXi logs. By gathering host log files onto a central host it can more easily monitor all hosts with a single tool. It can also do aggregate analysis and searching to look for such things as coordinated attacks on multiple hosts. Logging to a secure, centralized log server also helps prevent log tampering and also provides a long-term audit record.'
  desc 'check', %q(Verify the vSphere Syslog Collector syslog host has been configured. From the vSphere Client:  Select the host and click "Configuration >> Advanced Settings >> Syslog >> Global". Verify the 'Syslog.global.logHost' is set to the (site-specific) syslog server hostname.

If the 'Syslog.global.logHost' is unconfigured, this is a finding.)
  desc 'fix', %q(Step 1:  Verify the vSphere Syslog Collector syslog host has been configured. If not, install/enable the vSphere Syslog Collector.
Step 2:  From the vSphere Client:  Select the host and click "Configuration >> Advanced Settings >> Syslog >> Global".  
Step 3: Set 'Syslog.global.logHost' to the syslog server hostname.)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54081r798935_chk'
  tag severity: 'medium'
  tag gid: 'V-250646'
  tag rid: 'SV-250646r798937_rule'
  tag stig_id: 'SRG-OS-000215-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54035r798936_fix'
  tag 'documentable'
  tag legacy: ['SV-51267', 'V-39409']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
