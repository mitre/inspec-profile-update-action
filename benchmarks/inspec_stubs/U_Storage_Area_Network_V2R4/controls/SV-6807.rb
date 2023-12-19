control 'SV-6807' do
  title 'End-user platforms are directly attached to the Fibre Channel network or access storage devices directly.'
  desc 'End-user platforms should only be connected to servers that run applications that access the data found on the SAN devices.  SANs do not supply a robust user identification and authentication platform.  They depend on the servers and applications to authenticate the users and restrict access to users as required.
The IAO/NSO will ensure that end-user platforms are not directly attached to the Fibre Channel network and may not access storage devices directly.'
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that end-user platforms are not directly attached to the Fibre Channel network and may not access storage devices directly.  If the SAN is small with all of its components collocated, this can be done by a visual inspection but in most cases the reviewer will have to check the SAN network drawing.'
  desc 'fix', 'Develop a plan to remove end-user platforms from the SAN.  Obtain CM approval for the plan and implement the plan.'
  impact 0.3
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2586r1_chk'
  tag severity: 'low'
  tag gid: 'V-6660'
  tag rid: 'SV-6807r1_rule'
  tag stig_id: 'SAN04.024.00'
  tag gtitle: 'Fibre Channel network End-User Platform Restricted'
  tag fix_id: 'F-6255r1_fix'
  tag 'documentable'
  tag potential_impacts: 'End-user platforms attached to the SAN may be dependent upon the SAN for storage.  An alternate type of storage will need to be found for these platforms.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
  tag ia_controls: 'DCBP-1'
end
