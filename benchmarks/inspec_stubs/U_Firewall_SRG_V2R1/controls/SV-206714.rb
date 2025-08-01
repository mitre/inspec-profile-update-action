control 'SV-206714' do
  title 'The firewall must generate traffic log records when attempts are made to send packets between security zones that are not authorized to communicate.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Access for different security levels maintains separation between resources (particularly stored data) of different security domains.

The firewall can be configured to use security zones that are configured with different security policies based on risk and trust levels. These zones can be leveraged to prevent traffic from one zone from sending packets to another zone. For example, information from certain IP sources will be rejected if the destination matches specified security zones that are not authorized.'
  desc 'check', 'View the configuration of the firewall or the central audit server log records.

Verify the firewall generates traffic log records when attempts are made to send packets between security zones that are not authorized to communicate.

If the firewall does not generate traffic log records when attempts are made to send packets between security zones that are not authorized to communicate, this is a finding.'
  desc 'fix', 'Configure the firewall central audit server stanza to generate traffic log records when attempts are made to send packets between security zones that are not authorized to communicate.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6971r297921_chk'
  tag severity: 'medium'
  tag gid: 'V-206714'
  tag rid: 'SV-206714r604133_rule'
  tag stig_id: 'SRG-NET-000493-FW-000007'
  tag gtitle: 'SRG-NET-000493'
  tag fix_id: 'F-6971r297922_fix'
  tag 'documentable'
  tag legacy: ['SV-94137', 'V-79431']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
