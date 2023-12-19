control 'SV-240051' do
  title 'HAProxy must use a logging mechanism that is configured to alert the ISSO and SA in the event of a processing failure.'
  desc "An accurate and current audit trail is essential for maintaining a record of system activity. If the logging system fails, the SA must be notified and must take prompt action to correct the problem. Minimally, the system must log this event and the SA will receive this notification during the daily system log review. If feasible, active alerting (such as e-mail or paging) should be employed consistent with the site's established operations management systems and procedures."
  desc 'check', 'Interview the ISSO.

Determine if logging failure events are monitored, and warnings provided to the ISSO.

If logging failure events do not provide warnings in accordance with organization policies, this is a finding.

If alerts are not sent or the web server is not configured to use a dedicated logging tool that meets this requirement, this is a finding.'
  desc 'fix', 'Ensure logging failures result in warnings to the ISSO and SA at a minimum.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43284r665320_chk'
  tag severity: 'medium'
  tag gid: 'V-240051'
  tag rid: 'SV-240051r879570_rule'
  tag stig_id: 'VRAU-HA-000085'
  tag gtitle: 'SRG-APP-000108-WSR-000166'
  tag fix_id: 'F-43243r665321_fix'
  tag 'documentable'
  tag legacy: ['SV-99789', 'V-89139']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
