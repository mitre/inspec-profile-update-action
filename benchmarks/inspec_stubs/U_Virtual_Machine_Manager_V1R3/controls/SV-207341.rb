control 'SV-207341' do
  title 'The VMM must automatically audit account creation.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes. 

To address access requirements, many VMMs may be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM automatically audits account creation.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to automatically audit account creation.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7598r365433_chk'
  tag severity: 'medium'
  tag gid: 'V-207341'
  tag rid: 'SV-207341r378487_rule'
  tag stig_id: 'SRG-OS-000004-VMM-000040'
  tag gtitle: 'SRG-OS-000004'
  tag fix_id: 'F-7598r365434_fix'
  tag 'documentable'
  tag legacy: ['SV-71085', 'V-56825']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
