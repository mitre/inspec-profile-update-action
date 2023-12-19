control 'SV-6802' do
  title 'Unauthorized IP addresses are allowed Simple Network Management Protocol (SNMP) access to the SAN devices.'
  desc 'SNMP, by virtue of what it is designed to do, can be a large security risk. Because SNMP can obtain device information and set device parameters, unauthorized users can cause damage.  Restricting IP address that can access SNMP on the SAN devices will further limit the possibility of malicious access being made.
The IAO/NSO will ensure that only authorized IP addresses are allowed Simple Network Management Protocol (SNMP) access to the SAN devices.'
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that only authorized IP addresses are allowed Simple Network Management Protocol (SNMP) access to the SAN devices.  This can be done with by checking the ACLs for the SAN device ports.'
  desc 'fix', 'Develop a plan to restrict SNMP access to SAN devices to authorized IP addresses.  Obtain CM approval for the plan and implement the plan.'
  impact 0.7
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2581r1_chk'
  tag severity: 'high'
  tag gid: 'V-6656'
  tag rid: 'SV-6802r1_rule'
  tag stig_id: 'SAN04.022.00'
  tag gtitle: 'Authorized IP Addresses allowed for SNMP'
  tag fix_id: 'F-6253r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
  tag ia_controls: 'DCBP-1'
end
