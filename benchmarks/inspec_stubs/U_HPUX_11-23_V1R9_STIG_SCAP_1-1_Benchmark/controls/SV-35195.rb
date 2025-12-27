control 'SV-35195' do
  title 'The syslog daemon must not accept remote messages unless it is a syslog server documented using site-defined procedures.'
  desc "Unintentionally running a syslog server accepting remote messages puts the system at increased risk. Malicious syslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial of Service."
  desc 'fix', 'Edit the /etc/rc.config.d/syslogd configuration startup script and add the -N option to the syslogd command. Restart the syslogd service via the following command(s):
# /sbin/init.d/syslogd stop
# /sbin/init.d/syslogd start'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-12021'
  tag rid: 'SV-35195r1_rule'
  tag stig_id: 'GEN005480'
  tag gtitle: 'GEN005480'
  tag fix_id: 'F-31993r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
