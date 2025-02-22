control 'SV-206493' do
  title 'For the host and devices within its scope of coverage, the Central Log Server must be configured to send a real-time alert to the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) of all audit failure events, such as loss of communications with hosts and devices, or if log records are no longer being received.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit function and application operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less). User-configurable controls on the Central Log Server help avoid generating excessive numbers of alert messages. Define realistic alerting limits and thresholds to avoid creating excessive numbers of alerts for noncritical events.

This requirement must be mapped to the severity levels used by the system to denote a failure, active attack, attack involving multiple systems, and other critical notifications, at a minimum. However, note that the IDS/IDPS and other monitoring systems may already be configured for direct notification of many types of critical security alerts.'
  desc 'check', 'Examine the configuration.

Verify the system is configured to send an alert to the SA and ISSO, within seconds or less, when communication is lost with any host or device within the scope of coverage that may indicate an audit failure. 

Verify the system is configured to send an alert if hosts and devices stop sending log records to the Central Log Server.

If the Central Log Server is not configured to send a real-time alert to the SA and ISSO (at a minimum) of all audit failure events, this is a finding.'
  desc 'fix', 'For the host and devices within its scope of coverage, configure the Central Log Server to send an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events such as loss of communications with hosts and devices, or if log records are no longer being received.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6753r285720_chk'
  tag severity: 'low'
  tag gid: 'V-206493'
  tag rid: 'SV-206493r855300_rule'
  tag stig_id: 'SRG-APP-000360-AU-000130'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-6753r285721_fix'
  tag 'documentable'
  tag legacy: ['SV-95863', 'V-81149']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
