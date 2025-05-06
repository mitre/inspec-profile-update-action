control 'SV-38961' do
  title 'The system must employ a local firewall.'
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', 'Determine if the system is using a local firewall.

# lsfilt
# smitty ipsec4

If local firewall is not configured and running,  this is a finding.'
  desc 'fix', 'Configure the system to use a local firewall.  
Use SMIT to load the IPSEC filesets.
#smit install

Use SMIT to configure filters.
#smit ipsec4'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37947r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22582'
  tag rid: 'SV-38961r1_rule'
  tag stig_id: 'GEN008520'
  tag gtitle: 'GEN008520'
  tag fix_id: 'F-32366r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001118']
  tag nist: ['SC-7 (12)']
end
