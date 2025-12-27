control 'SV-242245' do
  title 'The Trend Micro SMS must generate an alert for all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'In the SMS client, ensure a SNMPv3 trap destination is configured. 

1. Navigate to Admin >> Server Properties >> SNMP.
2. View the NMS configuration.

If an NMS Trap Destination is not configured, this is a finding.'
  desc 'fix', "In the SMS client, configure a SNMPv3 trap destination is configured. Audit failure alerts are generated via SNMPv3 traps.

1. Navigate to Admin >> Server Properties >> SNMP >> Add.
2.  Enter the IPv4 or IPv6 address, Version 3, with the username, and authPriv keys configured that match the site's required attributes."
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45520r710740_chk'
  tag severity: 'medium'
  tag gid: 'V-242245'
  tag rid: 'SV-242245r710742_rule'
  tag stig_id: 'TIPP-NM-000390'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-45478r710741_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
