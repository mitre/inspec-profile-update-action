control 'SV-95897' do
  title 'The Central Log Server must be configured to notify the System Administrator (SA) and Information System Security Officer (ISSO), at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage.'
  desc 'Notification may be configured to be sent by the device, SNMP server, or Central Log Server. The best practice is for these notifications to be sent by a robust events management server. 

This is a function provided by most enterprise-level SIEMs. If the Central Log Server does not provide this function, it must forward the log records to a log server that does.'
  desc 'check', 'Note: This is not applicable (NA) if the Central Log Server (e.g., syslog, SIEM) does not perform analysis. This is NA if notifications are performed by another device. 

Examine the configuration.

Verify the Central Log Server is configured to notify the SA and ISSO, at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage.

If the Central Log Server is not configured to notify the SA and ISSO, at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to notify the SA and ISSO, at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80849r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81183'
  tag rid: 'SV-95897r1_rule'
  tag stig_id: 'SRG-APP-000516-AU-000350'
  tag gtitle: 'SRG-APP-000516-AU-000350'
  tag fix_id: 'F-87959r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
