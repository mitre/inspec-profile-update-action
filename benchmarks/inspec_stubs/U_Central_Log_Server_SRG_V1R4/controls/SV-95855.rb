control 'SV-95855' do
  title 'The Central Log Server must be configured to allow selection, capture, and view of all events related to a user session, host, or device when required by authorized users.'
  desc "If the system is not configured to select a user session to capture and view or produce a report, investigations into suspicious or harmful events would be hampered by the volume of information captured. The volume of information captured may also adversely impact the operation for the network.

This only includes auditable events. The Central Log Server (i.e., SIEM, syslog server) should be able to correlate across multiple devices and hosts within its span of control to provide an aggregated view of the single user's activity."
  desc 'check', 'Examine the configuration.

Verify the system is configured to allow selection, capture, and view of all events related to a user session, host, or device when required by authorized users.

If the Central Log Server is not configured to allow selection, capture, and view of all events related to a user session, host, or device when required by authorized users, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to allow selection, capture, and view of all events related to a user session, host, or device when required by authorized users.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80801r1_chk'
  tag severity: 'low'
  tag gid: 'V-81141'
  tag rid: 'SV-95855r1_rule'
  tag stig_id: 'SRG-APP-000354-AU-000080'
  tag gtitle: 'SRG-APP-000354-AU-000080'
  tag fix_id: 'F-87915r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001919']
  tag nist: ['AU-14 a']
end
