control 'SV-80785' do
  title 'The HP FlexFabric Switch must have a local account that will only be used as an account of last resort with full access to the network device.'
  desc 'In the event the network device loses connectivity to the management network authentication service, only a local account can gain access to the switch to perform configuration and maintenance. Without this capability, the network device is inaccessible to administrators.'
  desc 'check', 'Verify that the switch is configured with a local user that has full access by entering the following command:  display local-user user-name <name of user account>. 

The user role list should contain the following:  network-admin, network-operator

If the switch does not have a local user with full access, this is a finding.'
  desc 'fix', 'Configure the switch with a local user account that has network-admin and network-operator role.
[5900]local-user adminxxx
[5900-luser-manage-adminxxx]authorization-attribute  user-role network-admin   (or level=15)
[5900-luser-manage-adminxxx]authorization-attribute  user-role network-operator
[5900-luser-manage-adminxxx]service-type terminal
[5900-luser-manage-adminxxx]password hash xxxxxxxxxxxxxx'
  impact 0.7
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66941r1_chk'
  tag severity: 'high'
  tag gid: 'V-66295'
  tag rid: 'SV-80785r1_rule'
  tag stig_id: 'HFFS-ND-000140'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-72371r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
