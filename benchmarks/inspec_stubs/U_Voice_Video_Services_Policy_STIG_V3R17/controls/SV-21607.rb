control 'SV-21607' do
  title 'VVoIP core components are not assigned static addresses within the dedicated VVoIP address space'
  desc 'Assigning static addresses to core VVoIP devices permits tighter control using ACLs on firewalls and routers to help in the protection of these devices.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 
Ensure static addresses are assigned to the VVoIP core components within the dedicated VVoIP address space.'
  desc 'fix', 'Ensure static addresses are assigned to the VVoIP core components within the dedicated VVoIP address space. 

When defining the VVoIP system implementation plan and addressing scheme, assign static addresses to the VVoIP core components'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23792r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19545'
  tag rid: 'SV-21607r1_rule'
  tag stig_id: 'VVoIP 5220 (LAN)'
  tag gtitle: 'Deficient design: VVoIP addressing re: core comp.'
  tag fix_id: 'F-20238r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag responsibility: 'Information Assurance Officer'
end
