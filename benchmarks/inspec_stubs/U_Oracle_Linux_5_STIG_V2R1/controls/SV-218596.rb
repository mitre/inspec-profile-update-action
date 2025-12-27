control 'SV-218596' do
  title 'The syslog daemon must not accept remote messages unless it is a syslog server documented using site-defined procedures.'
  desc "Unintentionally running a syslog server accepting remote messages puts the system at increased risk.  Malicious syslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial of Service."
  desc 'check', "Ask the SA if the system is an authorized syslog server.  If the system is an authorized syslog server, this is not applicable.

Determine if the system's syslog service is configured to accept remote messages.

# ps -ef | grep syslogd

If the '-r' option is present, the system is configured to accept remote syslog messages, and this is a finding."
  desc 'fix', "Edit /etc/sysconfig/syslog to removing the '-r' in SYSLOGD_OPTIONS. Restart the syslogd service."
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20071r562825_chk'
  tag severity: 'medium'
  tag gid: 'V-218596'
  tag rid: 'SV-218596r603259_rule'
  tag stig_id: 'GEN005480'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20069r562826_fix'
  tag 'documentable'
  tag legacy: ['V-12021', 'SV-63531']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
