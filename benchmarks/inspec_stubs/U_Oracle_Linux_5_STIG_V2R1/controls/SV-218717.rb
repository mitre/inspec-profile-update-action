control 'SV-218717' do
  title 'The system must employ a local firewall.'
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', 'Determine if the system is using a local firewall.
# chkconfig --list iptables
If the service is not "on" in the standard runlevel (ordinarily 3 or 5), this is a finding.'
  desc 'fix', "Enable the system's local firewall.
# chkconfig iptables on
# service iptables start"
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20192r562939_chk'
  tag severity: 'medium'
  tag gid: 'V-218717'
  tag rid: 'SV-218717r603259_rule'
  tag stig_id: 'GEN008520'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-20190r562940_fix'
  tag 'documentable'
  tag legacy: ['V-22582', 'SV-63149']
  tag cci: ['CCI-002314', 'CCI-001118']
  tag nist: ['AC-17 (1)', 'SC-7 (12)']
end
