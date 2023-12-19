control 'SV-226609' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events.  Dynamic kernel modules can increase the attack surface of a system.  A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'check', 'Check /etc/security/audit_control file. 
# grep flags /etc/security/audit_control
If the as element is missing from the flags line, this is a finding.'
  desc 'fix', 'Edit /etc/security/audit_control and add the as flag to the flag parameter.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28770r483239_chk'
  tag severity: 'medium'
  tag gid: 'V-226609'
  tag rid: 'SV-226609r603265_rule'
  tag stig_id: 'GEN002825'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-28758r483240_fix'
  tag 'documentable'
  tag legacy: ['V-22383', 'SV-26524']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
