control 'SV-223201' do
  title 'The Juniper SRX Services Gateway must record time stamps for log records using Coordinated Universal Time (UTC).'
  desc 'If time stamps are not consistently applied and there is no common time reference, it is difficult to perform forensic analysis. UTC is normally used in DoD; however, Greenwich Mean Time (GMT) may be used if needed for mission requirements.'
  desc 'check', 'Verify the time zone is set to UTC.

[edit]
show system time-zone

If the time zone is not set to UTC, this is a finding.'
  desc 'fix', 'The following command sets the time zone to UTC.

[edit]
set system time-zone UTC'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24874r513290_chk'
  tag severity: 'medium'
  tag gid: 'V-223201'
  tag rid: 'SV-223201r513292_rule'
  tag stig_id: 'JUSX-DM-000065'
  tag gtitle: 'SRG-APP-000374-NDM-000299'
  tag fix_id: 'F-24862r513291_fix'
  tag 'documentable'
  tag legacy: ['SV-80973', 'V-66483']
  tag cci: ['CCI-001890']
  tag nist: ['AU-8 b']
end
