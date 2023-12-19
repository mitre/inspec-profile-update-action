control 'SV-207195' do
  title 'The VPN Gateway must generate log records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

VPN gateways often have a separate audit log for capturing VPN status and other information about the traffic (as opposed to the log capturing administrative and configuration actions). Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the VPN gateway logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured VPN gateway.'
  desc 'check', 'Verify the VPN Gateway generates log records containing information to establish what type of events occurred.

If the VPN Gateway does not generate log records containing information to establish what type of events occurred, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to generate log records containing information to establish what type of events occurred.'
  impact 0.3
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7455r378206_chk'
  tag severity: 'low'
  tag gid: 'V-207195'
  tag rid: 'SV-207195r608988_rule'
  tag stig_id: 'SRG-NET-000077-VPN-000280'
  tag gtitle: 'SRG-NET-000077'
  tag fix_id: 'F-7455r378207_fix'
  tag 'documentable'
  tag legacy: ['SV-106199', 'V-97061']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
