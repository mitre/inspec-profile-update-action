control 'SV-45991' do
  title 'The syslog daemon must not accept remote messages unless it is a syslog server documented using site-defined procedures.'
  desc "Unintentionally running a syslog server accepting remote messages puts the system at increased risk.  Malicious syslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial of Service."
  desc 'check', "#ps -ef | grep syslogd
If the '-r' option is present. This is a finding."
  desc 'fix', "Edit the syslog startup script and remove the '-r' option to the rsyslogd command, if it is there.  Command line options may also be provided by the RSYSLOGD_PARAMS variable in the /etc/sysconfig/syslog file.  This variable may be accessed using the ‘System’ > ‘/etc/sysconfig Editor’ in YaST.  It is found by expanding ‘+System’ and then ‘+Logging’.  Restart the syslog service after making any change to the runtime options."
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12021'
  tag rid: 'SV-45991r1_rule'
  tag stig_id: 'GEN005480'
  tag gtitle: 'GEN005480'
  tag fix_id: 'F-39356r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
