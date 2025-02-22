control 'SV-237215' do
  title 'ColdFusion must limit the time-out for requests waiting in the queue.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

By setting a timeout for requests in queue, the queue is kept clear and not filled by requests that can never be filled.  If an attacker were able to fill the queue with requests that never expired, the system would eventually fail.  For DoD systems, this setting must be set to 5 or lower and should match the "Timeout Requests After" value.'
  desc 'check', 'Within the Administrator Console, navigate to the "Request Tuning" page under the "Server Settings" menu.

If "Timeout requests waiting in queue after" setting is set higher than 5, this is a finding.'
  desc 'fix', 'Navigate to the "Request Tuning" page under the "Server Settings" menu.  Set "Timeout requests waiting in queue after" to 5 or less and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40434r641738_chk'
  tag severity: 'medium'
  tag gid: 'V-237215'
  tag rid: 'SV-237215r641740_rule'
  tag stig_id: 'CF11-05-000192'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-40397r641739_fix'
  tag 'documentable'
  tag legacy: ['SV-76993', 'V-62503']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
