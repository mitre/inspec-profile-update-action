control 'SV-95845' do
  title 'For devices and hosts within its scope of coverage, the Central Log Server must be configured to notify the System Administrator (SA) and Information System Security Officer (ISSO) when account modification events are received.'
  desc 'When application accounts are modified, user accessibility is affected. Accounts are used for identifying individual users or for identifying the application processes themselves. Sending notification of account modification events to the SA and ISSO is one method for mitigating this risk. Such a function greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

Notification may be configured to be sent by the device, SNMP server, or the Central Log Server. The best practice is for these notifications to be sent by a robust events management server.'
  desc 'check', 'Note: This is not applicable (NA) if notifications are performed by another device. 

Examine the configuration.

Verify the Central Log Server is configured to notify the SA and ISSO when account modification events are received for all devices and hosts within its scope of coverage.

If the Central Log Server is not configured to notify the SA and ISSO when account modification events are received for all devices and hosts within its scope of coverage, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to notify the SA and ISSO when account modification events are received for all devices and hosts within its scope of coverage.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80789r1_chk'
  tag severity: 'low'
  tag gid: 'V-81131'
  tag rid: 'SV-95845r1_rule'
  tag stig_id: 'SRG-APP-000292-AU-000420'
  tag gtitle: 'SRG-APP-000292-AU-000420'
  tag fix_id: 'F-87905r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
