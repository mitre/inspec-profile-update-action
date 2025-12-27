control 'SV-46049' do
  title 'The system must employ a local firewall.'
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', 'Determine if the system is using a local firewall.
# rcSuSEfirewall2 status
If the service is not "running”, this is a finding.'
  desc 'fix', "Enable the system's local firewall.
# rcSuSEfirewall2 start
# insserv SuSEfirewall2_init
# insserv SuSEfirewall2_setup"
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43320r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22582'
  tag rid: 'SV-46049r1_rule'
  tag stig_id: 'GEN008520'
  tag gtitle: 'GEN008520'
  tag fix_id: 'F-39405r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001118']
  tag nist: ['SC-7 (12)']
end
