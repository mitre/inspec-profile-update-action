control 'SV-26977' do
  title "The system's local firewall must implement a deny-all, allow-by-exception policy."
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', %q(Check the firewall rules for a default deny rule. 
# ipfstat -i | sed -e 's/^[ \t]*//' | tr '\011' ' ' | tr -s ' ' | grep -v "^#" | grep "block"

An example of a default deny rule:
block in log quick on ne3 from any to any

If there is no default deny rule, this is a finding.)
  desc 'fix', 'Edit /etc/opt/ipf/ipf.conf and add a default deny rule and restart the ipfilter service.
# /sbin/init.d/ipfboot stop 
# /sbin/init.d/ipfboot start'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36794r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22583'
  tag rid: 'SV-26977r1_rule'
  tag stig_id: 'GEN008540'
  tag gtitle: 'GEN008540'
  tag fix_id: 'F-32172r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
