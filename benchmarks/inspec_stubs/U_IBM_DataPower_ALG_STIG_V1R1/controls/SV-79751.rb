control 'SV-79751' do
  title 'The DataPower Gateway must provide an immediate real-time alert to, at a minimum, the SCA and ISSO, of all audit failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server.'
  desc 'Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Examine configuration of Log targets (type “Log Target” in navigation search box) to verify a target that delivers Critical messages.

If no log targets are configured, this is a finding.'
  desc 'fix', 'Log Target to send all Critical log messages to the desired destination.

Search Bar “Log Target” >> Add >> Name log target name >> Target Type “SOAP” >> URL dest url 

Event Subscriptions tab >> Add >> Event Category “all” >> Minimum Event Priority “critical”'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65889r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65261'
  tag rid: 'SV-79751r1_rule'
  tag stig_id: 'WSDP-AG-000091'
  tag gtitle: 'SRG-NET-000335-ALG-000053'
  tag fix_id: 'F-71201r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
