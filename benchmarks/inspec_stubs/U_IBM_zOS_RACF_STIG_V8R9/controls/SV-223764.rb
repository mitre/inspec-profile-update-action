control 'SV-223764' do
  title 'The IBM z/OS System Administrator (SA) must develop a process to notify appropriate personnel when accounts are deleted.'
  desc 'Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Ask the system Administrator for the documented process to notify appropriate personnel when accounts are deleted.

If there is no documented process, this is a finding.'
  desc 'fix', 'Develop a documented develop a process to notify appropriate personnel when accounts are deleted.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25437r514980_chk'
  tag severity: 'medium'
  tag gid: 'V-223764'
  tag rid: 'SV-223764r604139_rule'
  tag stig_id: 'RACF-OS-000080'
  tag gtitle: 'SRG-OS-000276-GPOS-00106'
  tag fix_id: 'F-25425r514981_fix'
  tag 'documentable'
  tag legacy: ['V-98235', 'SV-107339']
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
