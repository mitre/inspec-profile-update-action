control 'SV-26524' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events.  Dynamic kernel modules can increase the attack surface of a system.  A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'fix', 'Edit /etc/security/audit_control and add the as flag to the flag parameter.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22383'
  tag rid: 'SV-26524r1_rule'
  tag stig_id: 'GEN002825'
  tag gtitle: 'GEN002825'
  tag fix_id: 'F-23766r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
