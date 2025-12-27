control 'SV-104501' do
  title 'Symantec ProxySG must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Verify the Symantec ProxySG is configured to use authoritative NTP servers (the NTP protocol itself enforces periodic checks at least every 24 hours).

1. Log on to the Web Management Console.
2. Click Configuration >> General >> Clock.
3. Confirm that the value of the "Query interval (minutes)" field is at least 1440 (24 hours in minutes). 
4. Click "NTP", and confirm that the desired authoritative time servers are present.

If Symantec ProxySG does not compare internal information system clocks at least every 24 hours with an authoritative time server, this is a finding.'
  desc 'fix', 'Configure the Symantec ProxySG to use authoritative NTP servers (the NTP protocol itself enforces periodic checks at least every 24 hours).

1. Log on to the Web Management Console.
2. Select "Configuration", then "General", then "Clock".
3. Enter the desired time sync period into the "Query interval (minutes) field and click Apply. 
4. Click "NTP", then "New", then "Add" and enter each desired authoritative time server.
5. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94671'
  tag rid: 'SV-104501r1_rule'
  tag stig_id: 'SYMP-NM-000100'
  tag gtitle: 'SRG-APP-000371-NDM-000296'
  tag fix_id: 'F-100789r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
