control 'SV-227072' do
  title "The system's local firewall must implement a deny-all, allow-by-exception policy."
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', 'If the system is not a global zone, this vulnerability is not applicable.

Check the firewall rules for a default deny rule. 
# ipfstat -i

An example of a default deny rule is:
block in log quick on ne3 from any to any.

If there is no default deny rule, this is a finding.'
  desc 'fix', 'Edit /etc/ipf/ipf.conf and add a default deny rule.
Restart the ipfilter service.
# svcadm restart network/ipfilter'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29234r485594_chk'
  tag severity: 'medium'
  tag gid: 'V-227072'
  tag rid: 'SV-227072r603265_rule'
  tag stig_id: 'GEN008540'
  tag gtitle: 'SRG-OS-000297'
  tag fix_id: 'F-29222r485595_fix'
  tag 'documentable'
  tag legacy: ['V-22583', 'SV-26976']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
