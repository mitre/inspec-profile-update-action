control 'SV-45984' do
  title 'The system must not be used as a syslog server (loghost) for systems external to the enclave.'
  desc 'Syslog messages are typically unencrypted, may contain sensitive information, and are restricted to the enclave.'
  desc 'check', 'Ask the SA if the loghost server is collecting data for hosts outside the local enclave. If it is, this is a finding.'
  desc 'fix', 'Configure the hosts outside of the local enclave to not log to this system.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43266r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12020'
  tag rid: 'SV-45984r1_rule'
  tag stig_id: 'GEN005440'
  tag gtitle: 'GEN005440'
  tag fix_id: 'F-39349r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
