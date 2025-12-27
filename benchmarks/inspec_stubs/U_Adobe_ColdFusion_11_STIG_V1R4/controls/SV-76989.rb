control 'SV-76989' do
  title 'ColdFusion must set a timeout for requests.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

The "Timeout Requests after" setting is used to terminate requests that have not been fulfilled within the set time. This parameter prevents unusually long requests from occupying server resources and impairing performance or denying other requests. 
This setting is system dependent and may be changed based on the performance capabilities of the underlying system hardware.  Unless custom system tuning parameters are required and specifically documented, this value should be set to "5" or less.  
The vendor also recommends the "Timeout requests waiting in queue after" setting be set to the same value.'
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

Review system documentation. Determine if the "Timeout Requests after" setting has been tuned to account for application and system performance.

If "Timeout Requests after seconds" is not set to "5" or is not set in accordance with the documented tuning parameters, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Check "Timeout Requests after seconds" and set the value to "5" or to the documented tuned value and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63303r4_chk'
  tag severity: 'medium'
  tag gid: 'V-62499'
  tag rid: 'SV-76989r2_rule'
  tag stig_id: 'CF11-05-000190'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-68419r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
