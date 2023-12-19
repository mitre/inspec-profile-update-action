control 'SV-223763' do
  title 'The IBM z/OS System Administrator (SA) must develop a process to notify appropriate personnel when accounts are modified.'
  desc 'Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Ask the system Administrator for the documented process to notify appropriate personnel when accounts are modified.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented develop a process to notify appropriate personnel when accounts are modified.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25436r514977_chk'
  tag severity: 'medium'
  tag gid: 'V-223763'
  tag rid: 'SV-223763r604139_rule'
  tag stig_id: 'RACF-OS-000070'
  tag gtitle: 'SRG-OS-000275-GPOS-00105'
  tag fix_id: 'F-25424r514978_fix'
  tag 'documentable'
  tag legacy: ['V-98233', 'SV-107337']
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
