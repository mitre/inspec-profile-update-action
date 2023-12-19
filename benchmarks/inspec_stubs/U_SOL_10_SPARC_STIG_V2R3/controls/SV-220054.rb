control 'SV-220054' do
  title 'The syslog daemon must not accept remote messages unless it is a syslog server documented using site-defined procedures.'
  desc "Unintentionally running a syslog server accepting remote messages puts the system at increased risk.  Malicious syslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial of Service."
  desc 'check', '# svcprop system-log | grep log_from_remote

If the config/log_from_remote value is not false, this is a finding.'
  desc 'fix', '# svccfg -s system-log setprop config/log_from_remote=false
# svcadm refresh system-log'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21763r485285_chk'
  tag severity: 'medium'
  tag gid: 'V-220054'
  tag rid: 'SV-220054r603265_rule'
  tag stig_id: 'GEN005480'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21762r485286_fix'
  tag 'documentable'
  tag legacy: ['V-12021', 'SV-28431']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
