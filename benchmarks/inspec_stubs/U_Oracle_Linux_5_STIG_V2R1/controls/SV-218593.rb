control 'SV-218593' do
  title 'The system must not be used as a syslog server (loghost) for systems external to the enclave.'
  desc 'Syslog messages are typically unencrypted, may contain sensitive information, and are restricted to the enclave.'
  desc 'check', 'Ask the SA if the loghost server is collecting data for hosts outside the local enclave. If it is, this is a finding.'
  desc 'fix', 'Configure the hosts outside of the local enclave to not log to this system.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20068r555977_chk'
  tag severity: 'medium'
  tag gid: 'V-218593'
  tag rid: 'SV-218593r603259_rule'
  tag stig_id: 'GEN005440'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20066r555978_fix'
  tag 'documentable'
  tag legacy: ['V-12020', 'SV-63495']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
