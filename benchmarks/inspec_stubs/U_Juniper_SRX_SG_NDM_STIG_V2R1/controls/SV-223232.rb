control 'SV-223232' do
  title 'The Juniper SRX Services Gateway must terminate a device management session if the keep-alive count is exceeded.'
  desc 'Configuring the keep-alive for management protocols mitigates the risk of an open connection being hijacked by an attacker.

The keep-alive messages and the interval between each message are used to force the system to disconnect a user that has lost network connectivity to the device. This differs from inactivity timeouts because the device does not wait the 10 minutes to log the user out but, instead, immediately logs the user out if the number of keep-alive messages are exceeded. The interval between messages should also be configured. These values should be set to an organization-defined value based on mission requirements and network performance.'
  desc 'check', 'Verify this setting by entering the following commands in configuration mode.

[edit]
show system services ssh

If the keep-alive count and keep-alive interval is not set to an organization-defined value, this is a finding.'
  desc 'fix', 'Configure this setting by entering the following commands in configuration mode.

[edit]
set system services ssh client-alive-count-max <organization-defined value>
set system services ssh client-alive-interval <organization-defined value>'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24905r513383_chk'
  tag severity: 'medium'
  tag gid: 'V-223232'
  tag rid: 'SV-223232r539622_rule'
  tag stig_id: 'JUSX-DM-000157'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-24893r513384_fix'
  tag 'documentable'
  tag legacy: ['SV-81029', 'V-66539']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
