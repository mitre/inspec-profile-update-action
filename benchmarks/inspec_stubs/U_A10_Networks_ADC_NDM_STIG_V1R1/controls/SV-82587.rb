control 'SV-82587' do
  title 'The A10 Networks ADC must restrict management connections to the management network.'
  desc 'Remote administration is inherently dangerous because anyone with a sniffer and access to the right LAN segment could acquire the device account and password information. With this intercepted information they could gain access to the infrastructure and cause denial of service attacks, intercept sensitive information, or perform other destructive actions.'
  desc 'check', 'Ask the device administrator what the subnet assigned to the management network is and which access-list is used to restrict management traffic.

Review the device configuration.

The following command displays a configured access-list:
show access-list [ipv4 | ipv6] [acl-id]

If no access list for the management network is configured, this is a finding.

If the access list for the management network does not restrict traffic solely to the management network, this is a finding.

The following command displays information about the management interface:
show interface management

If the access list is not applied to the management interface, this is a finding.'
  desc 'fix', 'Configure an ACL or filter to restrict management access to the device from only the management network. 

The following commands configure an access control list that only allows traffic from the management network and logs denied traffic:
access-list [acl-num] permit
access-list [acl-num] permit source-ipaddr {filter-mask | /mask-length}
access-list [acl-num] deny any log
Note: The source-ipadd and mask must be the subnet used for the management network.

The following commands apply the ACL to the management interface:
interface management
access-list [acl-num] in
Note that acl-num is the number assigned to the ACL configured above.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68657r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68097'
  tag rid: 'SV-82587r1_rule'
  tag stig_id: 'AADC-NM-000143'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-74211r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
