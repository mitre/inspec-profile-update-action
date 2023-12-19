control 'SV-237039' do
  title 'The A10 Networks ADC must not have any unnecessary or unapproved virtual servers configured.'
  desc 'A deny-all, permit-by-exception network communications traffic policy ensures that only those connections which are essential and approved are allowed.

A virtual server is an instance where the device accepts traffic from outside hosts and redirects traffic to one or more real servers. In keeping with a deny-all, permit-by-exception policy, the services that the device provides to outside hosts must be only those that are necessary, documented, and approved.'
  desc 'check', 'Review the configured servers, service groups, and virtual servers. 

The following command shows information for SLB servers:
show slb server

The following command shows information for service groups (multiple servers):
show slb service-group

The following command shows information for virtual servers (the services visible to outside hosts):
show slb virtual-server

Ask the Administrator for the list of approved services being provided by the device and compare this against the output of the command listed above. 

If there are more configured virtual servers than are approved, this is a finding.'
  desc 'fix', 'Do not configure a server, service group, or virtual server for any unnecessary or unapproved service.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40258r639562_chk'
  tag severity: 'medium'
  tag gid: 'V-237039'
  tag rid: 'SV-237039r639564_rule'
  tag stig_id: 'AADC-AG-000047'
  tag gtitle: 'SRG-NET-000202-ALG-000124'
  tag fix_id: 'F-40221r639563_fix'
  tag 'documentable'
  tag legacy: ['SV-82463', 'V-67973']
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
