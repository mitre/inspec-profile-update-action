control 'SV-16766' do
  title 'ESX Server required services are not documented.'
  desc 'Once the ESX Server is configured and operating, all required services needed for operation will be documented. Undocumented services running on the ESX Server opens up ports and vulnerabilities that may be exploited to gain access to the server.  These services also consume processor cycles and memory. The ESX Server shares resources with virtual machines and the service console, and all excess resources are allocated based on the priorities configured.'
  desc 'check', 'Request the required services documentation from the IAO/SA. If no documentation can be produced, this is a finding. Compare this to the services running on the ESX Server by performing the following on the service console:
#netstat –an
If a discrepancy exists between the services documented, and the services running, this is a finding.'
  desc 'fix', 'Document all required services for the ESX Server.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16178r1_chk'
  tag severity: 'low'
  tag gid: 'V-15827'
  tag rid: 'SV-16766r1_rule'
  tag stig_id: 'ESX0350'
  tag gtitle: 'ESX Server required services are not documented.'
  tag fix_id: 'F-15779r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
