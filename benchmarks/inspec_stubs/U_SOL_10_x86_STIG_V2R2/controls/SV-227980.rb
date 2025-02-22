control 'SV-227980' do
  title 'The system must employ a local firewall.'
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', 'Determine the zone that you are currently securing.

# zonename

If the command output is "global", only the "phys" and "SR-IOV" interfaces assigned to the global zone require inspection. If using a non-Global zone, all "phys" and "SR-IOV" interfaces assigned to the zone require inspection.

Determine if the system is using a local firewall.
# svcs network/ipfilter
If the service is not online, this is a finding.'
  desc 'fix', "Enable the system's local firewall.
# svcadm enable network/ipfilter"
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30142r490378_chk'
  tag severity: 'medium'
  tag gid: 'V-227980'
  tag rid: 'SV-227980r603266_rule'
  tag stig_id: 'GEN008520'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30130r490379_fix'
  tag 'documentable'
  tag legacy: ['V-22582', 'SV-26974']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
