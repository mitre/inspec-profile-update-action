control 'SV-12521' do
  title 'The system must not be used as a syslog server (log host) for systems external to the enclave.'
  desc 'Syslog messages are typically unencrypted and may contain sensitive information and are, therefore, restricted to the enclave.'
  desc 'check', 'Ask the SA if the log host server is collecting data for hosts outside the local enclave.  If it is, this is a finding.'
  desc 'fix', 'Configure the hosts outside of the local enclave to not log to this system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7984r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12020'
  tag rid: 'SV-12521r2_rule'
  tag stig_id: 'GEN005440'
  tag gtitle: 'GEN005440'
  tag fix_id: 'F-11279r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
