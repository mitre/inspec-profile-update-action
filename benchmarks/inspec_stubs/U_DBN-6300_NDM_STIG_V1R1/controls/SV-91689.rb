control 'SV-91689' do
  title 'The DBN-6300 must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC).'
  desc 'If time stamps are not consistently applied and there is no common time reference, it is difficult to perform forensic analysis.'
  desc 'check', 'Verify the time zone is configured for "UTC".

Navigate to Settings >> Initial Configuration >> Time.

View the "Time Zone" box.

If the Time Zone is not set to "UTC", this is a finding.'
  desc 'fix', 'Configure the time zone to "UTC".

Navigate to Settings >> Initial Configuration >> Time and click on "NTP".

Click on the drop-down box next to the "Time Zone" label.

Select "UTC" underneath the "Etc" category.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76619r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76993'
  tag rid: 'SV-91689r1_rule'
  tag stig_id: 'DBNW-DM-000103'
  tag gtitle: 'SRG-APP-000374-NDM-000299'
  tag fix_id: 'F-83689r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001890']
  tag nist: ['AU-8 b']
end
