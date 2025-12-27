control 'SV-253871' do
  title 'The Tanium application must limit the bandwidth used in communicating with endpoints to prevent a denial-of-service (DoS) condition at the server.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of applications to mitigate the impact of DoS attacks that have occurred or are ongoing on application availability. For each application, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Bandwidth Throttles".

4. Work with the Tanium administrator to confirm settings. 

If settings are not based on organization needs, this is a finding. 

For more information, refer to https://docs.tanium.com/platform_user/platform_user/console_bandwidth_throttling.html.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Bandwidth Throttles".

4. Click "Add" on the line for "Global Throttle for All Data".

5. Work with the Tanium administrator to configure the required bandwidth throttles.

6. Click "Save".

7. Work with the Tanium administrator to confirm or set settings for the remaining options:

- Global Throttle for Package Files.
- Global Throttle for Sensors.
- Site Throttles.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57323r842639_chk'
  tag severity: 'medium'
  tag gid: 'V-253871'
  tag rid: 'SV-253871r850265_rule'
  tag stig_id: 'TANS-SV-000062'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-57274r842640_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
