control 'SV-12522' do
  title 'The syslog daemon must not accept remote messages unless it is a syslog server documented using site-defined procedures.'
  desc "Unintentionally running a syslog server that accepts remote messages puts the system at increased risk.  Malicious syslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial-of-Service."
  desc 'check', 'Determine if the syslog daemon accepts remote messages.  If it does, this is a finding.'
  desc 'fix', 'Configure the system syslog daemon to not accept messages from remote hosts.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7986r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12021'
  tag rid: 'SV-12522r2_rule'
  tag stig_id: 'GEN005480'
  tag gtitle: 'GEN005480'
  tag fix_id: 'F-11280r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
