control 'SV-37810' do
  title 'The system must not be used as a syslog server (loghost) for systems external to the enclave.'
  desc 'Syslog messages are typically unencrypted, may contain sensitive information, and are restricted to the enclave.'
  desc 'check', 'Ask the SA if the loghost server is collecting data for hosts outside the local enclave. If it is, this is a finding.'
  desc 'fix', 'Configure the hosts outside of the local enclave to not log to this system.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37010r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12020'
  tag rid: 'SV-37810r1_rule'
  tag stig_id: 'GEN005440'
  tag gtitle: 'GEN005440'
  tag fix_id: 'F-32274r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
