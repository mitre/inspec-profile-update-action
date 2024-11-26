control 'SV-220053' do
  title 'The system must not be used as a syslog server (log host) for systems external to the enclave.'
  desc 'Syslog messages are typically unencrypted and may contain sensitive information and are, therefore, restricted to the enclave.'
  desc 'check', 'Ask the SA if the log host server is collecting data for hosts outside the local enclave.  If it is, this is a finding.'
  desc 'fix', 'Configure the hosts outside of the local enclave to not log to this system.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21762r485276_chk'
  tag severity: 'medium'
  tag gid: 'V-220053'
  tag rid: 'SV-220053r603265_rule'
  tag stig_id: 'GEN005440'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21761r485277_fix'
  tag 'documentable'
  tag legacy: ['SV-41515', 'V-12020']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
