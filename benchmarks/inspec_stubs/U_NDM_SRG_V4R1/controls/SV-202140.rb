control 'SV-202140' do
  title 'The network device must limit the number of concurrent sessions to an organization-defined number for each administrator account and/or administrator account type.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Review the network device configuration to see if the device limits the number of concurrent sessions to an organization-defined number for all administrator accounts and/or administrator account types. 

If the network device does not limit the number of concurrent sessions to an organization-defined number for each administrator account and/or administrator account type, this is a finding.'
  desc 'fix', 'Configure the network device to limit the number of concurrent sessions to an organization-defined number for all administrator accounts and/or administrator account types.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2091r382082_chk'
  tag severity: 'medium'
  tag gid: 'V-202140'
  tag rid: 'SV-202140r395442_rule'
  tag stig_id: 'SRG-APP-000001-NDM-000200'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-2092r382083_fix'
  tag 'documentable'
  tag legacy: ['SV-69273', 'V-55027']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
