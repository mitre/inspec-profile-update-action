control 'SV-38403' do
  title 'The system must employ a local firewall.'
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', %q(Determine if the system is using a local firewall. 
# cat /etc/rc.config.d/ipfconf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | cut -f 3,3 -d " " | grep "IPF_START"

If IPF_START is not set to 1, this is a finding.)
  desc 'fix', 'Set IPF_START=1 in /etc/rc.config.d/ipfconf.

Refresh/restart.
# /sbin/init.d/ipfboot start'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36793r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22582'
  tag rid: 'SV-38403r1_rule'
  tag stig_id: 'GEN008520'
  tag gtitle: 'GEN008520'
  tag fix_id: 'F-32171r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001118']
  tag nist: ['SC-7 (12)']
end
