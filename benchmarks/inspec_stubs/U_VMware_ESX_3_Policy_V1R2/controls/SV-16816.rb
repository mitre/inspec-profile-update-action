control 'SV-16816' do
  title 'Users assigned to VirtualCenter groups are not documented.'
  desc 'Ensuring privileged group membership is controlled requires updates to group documentation, and periodic reviews to determine that unauthorized users are not members.  If an unauthorized user is able to gain membership to the Database Administrator group, Virtual Machine Administrator group, or the Resource Administrator group, etc., that user would be able to display, add, or change permissions to objects that could impact the confidentiality, integrity, or availability of an entire virtualization structure.'
  desc 'check', 'Request a copy of the VirtualCenter group documentation listing the users in the following groups:

Database Administrators,
Virtual Machine Administrators,
Resource Pool Administrators,
ESX Administrators,
Virtual Machine Power Users, and
All Custom Roles

If documentation can not be produced, this is a finding.  Compare the documentation to the actual users assigned in the groups.  If there are discrepancies, this is a finding.'
  desc 'fix', 'Document all the users assigned to all VirtualCenter groups.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16233r1_chk'
  tag severity: 'low'
  tag gid: 'V-15875'
  tag rid: 'SV-16816r1_rule'
  tag stig_id: 'ESX0760'
  tag gtitle: 'VirtualCenter groups are not documented'
  tag fix_id: 'F-15835r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end
