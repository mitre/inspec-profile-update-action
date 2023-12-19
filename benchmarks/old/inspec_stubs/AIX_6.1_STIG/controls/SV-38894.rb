control 'SV-38894' do
  title 'The syslog daemon must not accept remote messages unless it is a syslog server documented using site-defined procedures.'
  desc "Unintentionally running a syslog server that accepts remote messages puts the system at increased risk.  Malicious syslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial of Service."
  desc 'check', 'Verify syslogd is running with the -R option.
#ps -ef | grep syslogd | grep -v grep

If the -R option is not present, this is a finding.'
  desc 'fix', "Change the syslogd arguments in the src subsystem control and restart the syslogd daemon.
# chssys -s syslogd -a '-R'
# stopsrc -s syslogd
# startsrc -s syslogd"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37890r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12021'
  tag rid: 'SV-38894r1_rule'
  tag stig_id: 'GEN005480'
  tag gtitle: 'GEN005480'
  tag fix_id: 'F-33141r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
