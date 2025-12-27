control 'SV-95847' do
  title 'For devices and hosts within its scope of coverage, the Central Log Server must notify the System Administrator (SA) and Information System Security Officer (ISSO) when events indicating account disabling actions are received.'
  desc 'When application accounts are disabled, user accessibility is affected. Accounts are used for identifying individual users or for identifying the application processes themselves. Sending notification of account disabling events to the SA and ISSO is one method for mitigating this risk. Such a function greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

Notification may be configured to be sent by the device, SNMP server, or Central Log Server. The best practice is for these notifications to be sent by a robust events management server.'
  desc 'check', 'Note: This is not applicable (NA) if notifications are performed by another device. 

Examine the configuration.

Verify the Central Log Server is configured to notify the SA and ISSO when events indicating account disabling actions are received for all devices and hosts within its scope of coverage.

If the Central Log Server does not notify the SA and ISSO when events indicating account disabling actions are received, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to notify the SA and ISSO when events indicating account disabling actions are received for all devices and hosts within its scope of coverage.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80791r1_chk'
  tag severity: 'low'
  tag gid: 'V-81133'
  tag rid: 'SV-95847r1_rule'
  tag stig_id: 'SRG-APP-000293-AU-000430'
  tag gtitle: 'SRG-APP-000293-AU-000430'
  tag fix_id: 'F-87907r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
