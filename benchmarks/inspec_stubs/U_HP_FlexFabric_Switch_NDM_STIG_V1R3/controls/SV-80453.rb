control 'SV-80453' do
  title 'The HP FlexFabric Switch must limit the number of concurrent sessions to an organization-defined number for each administrator account and/or administrator account type.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to see if it limits the number of concurrent sessions to an organization-defined number for all administrator accounts and/or administrator account types:

[HP] display local-user

Device management user test:
  State:                     Active
  Service type:              None
  Access limit:              Enabled           Max access number: 3
  Current access number:     0
  User group:                system
  Bind attributes:
  Authorization attributes:
    Work directory:          cfa0:
    User role list:          network-admin

If "Max access number:" line is not present, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to limit the number of concurrent sessions to an organization-defined number for all administrator accounts and administrator account types as shown in the following example:

[HP] local-user admin
[HP-luser-manage-admin] access-limit 3'
  impact 0.3
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66611r1_chk'
  tag severity: 'low'
  tag gid: 'V-65963'
  tag rid: 'SV-80453r1_rule'
  tag stig_id: 'HFFS-ND-000001'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-72039r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
