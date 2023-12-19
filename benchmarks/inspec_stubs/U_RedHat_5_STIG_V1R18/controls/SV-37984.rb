control 'SV-37984' do
  title 'The system must employ a local firewall.'
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', 'Determine if the system is using a local firewall.
# chkconfig --list iptables
If the service is not "on" in the standard runlevel (ordinarily 3 or 5), this is a finding.'
  desc 'fix', "Enable the system's local firewall.
# chkconfig iptables on
# service iptables start"
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37285r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22582'
  tag rid: 'SV-37984r1_rule'
  tag stig_id: 'GEN008520'
  tag gtitle: 'GEN008520'
  tag fix_id: 'F-32522r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001118']
  tag nist: ['SC-7 (12)']
end
