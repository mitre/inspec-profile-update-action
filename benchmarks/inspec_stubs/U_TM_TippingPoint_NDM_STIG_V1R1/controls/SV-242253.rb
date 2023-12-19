control 'SV-242253' do
  title 'The TippingPoint SMS must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'In the SMS client, ensure the remote system is configured to generate all audit records. 

1. Navigate to Admin >> Server properties >> Syslog. 
2. Verify the configuration enables TCP.
3. Verify Device Audit, Device System, SMS Audit, and SMS System log types are enabled and configured.

If syslog is not configured to use TCP or does not include the four log types, this is a finding.'
  desc 'fix', 'In the SMS client, ensure the remote system is configured to generate all audit records.

1. Navigate to Admin >> Server properties >> Syslog >> New.
2. Click enable.
3. Click TCP (required for DoD).
4. Under Log Type, select "Device Audit".
5. Facility is "Log Audit". 
6. Timestamp: SMS Current Time. 
7. Check "Include SMS hostname in Header". 
8. Click OK. 
9. Repeat these steps for the following three other Log Types: Device System, SMS Audit, and SMS System.'
  impact 0.3
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45528r710764_chk'
  tag severity: 'low'
  tag gid: 'V-242253'
  tag rid: 'SV-242253r710766_rule'
  tag stig_id: 'TIPP-NM-000520'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-45486r710765_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
