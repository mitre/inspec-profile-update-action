control 'SV-76993' do
  title 'ColdFusion must limit the time-out for requests waiting in the queue.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

By setting a timeout for requests in queue, the queue is kept clear and not filled by requests that can never be filled.  If an attacker were able to fill the queue with requests that never expired, the system would eventually fail.  For DoD systems, this setting must be set to 5 or lower and should match the "Timeout Requests After" value.'
  desc 'check', 'Within the Administrator Console, navigate to the "Request Tuning" page under the "Server Settings" menu.

If "Timeout requests waiting in queue after" setting is set higher than 5, this is a finding.'
  desc 'fix', 'Navigate to the "Request Tuning" page under the "Server Settings" menu.  Set "Timeout requests waiting in queue after" to 5 or less and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63307r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62503'
  tag rid: 'SV-76993r1_rule'
  tag stig_id: 'CF11-05-000192'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-68423r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
