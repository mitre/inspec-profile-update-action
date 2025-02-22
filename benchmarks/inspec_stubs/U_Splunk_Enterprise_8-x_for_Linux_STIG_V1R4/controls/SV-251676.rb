control 'SV-251676' do
  title 'Splunk Enterprise must be configured with a report to notify the System Administrator (SA) and Information System Security Officer (ISSO), at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage.'
  desc 'Detecting when multiple systems are showing anomalies can often indicate an attack. Notifying appropriate personnel can initiate a proper response and mitigation of the attack.'
  desc 'check', 'Interview the SA to verify that a report exists to notify the SA and ISSO, at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage.

Interview the ISSO to confirm receipt of this report.

If a report does not exist, or the ISSO does not confirm receipt of this report, this is a finding.'
  desc 'fix', 'Configure Splunk Enterprise, using the Reporting and Alert tools, to notify the SA and ISSO, at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55114r808262_chk'
  tag severity: 'medium'
  tag gid: 'V-251676'
  tag rid: 'SV-251676r879887_rule'
  tag stig_id: 'SPLK-CL-000280'
  tag gtitle: 'SRG-APP-000516-AU-000350'
  tag fix_id: 'F-55068r808263_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
