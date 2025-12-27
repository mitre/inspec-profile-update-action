control 'SV-6803' do
  title 'The IP addresses of the hosts permitted SNMP access to the SAN management devices do not belong to the internal network.'
  desc 'SNMP, by virtue of what it is designed to do, can be a large security risk. Because SNMP can obtain device information and set device parameters, unauthorized users can cause damage.  Therefore access to a SAN device from an IP address outside of the internal network will not be allowed.
The IAO/NSO will ensure IP addresses of the hosts that are permitted SNMP access to the SAN management devices belong to the internal network.'
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that the IP addresses of the hosts permitted SNMP access to the SAN management devices belong to the internal network.  The ACLs for the SAN ports should be checked.'
  desc 'fix', 'Develop a plan to restrict SNMP access to SAN devices to only internal network IP addresses.  Obtain CM approval of the plan and implement the plan.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2583r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6657'
  tag rid: 'SV-6803r1_rule'
  tag stig_id: 'SAN04.023.00'
  tag gtitle: 'Only Internal Network SNMP Access to SAN'
  tag fix_id: 'F-6254r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end
