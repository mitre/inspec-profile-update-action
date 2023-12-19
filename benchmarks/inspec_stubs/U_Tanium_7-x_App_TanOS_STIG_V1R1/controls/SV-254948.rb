control 'SV-254948' do
  title 'The Tanium application must limit the bandwidth used in communicating with endpoints to prevent a denial of service (DoS) condition at the server.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of applications to mitigate the impact of DoS attacks that have occurred or are ongoing on application availability. For each application, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Bandwidth Throttles".

4. Work with the Tanium Administrator to confirm settings.  

If bandwidth throttles are not configured, this is a finding.

For more information, see the following: https://docs.tanium.com/platform_user/platform_user/console_bandwidth_throttling.html.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under Configuration, select "Bandwidth Throttles".

4. Click "Add" on the line for "Global Throttle for All Data".

5. Work with Tanium Administrator to configure the required bandwidth throttles.

6. Click "Save".

7. Work with the Tanium Administrator to confirm or set settings for the remaining options:

    a) Global Throttle for Package Files
    b) Global Throttle for Sensors
    c) Site Throttles'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58561r867742_chk'
  tag severity: 'medium'
  tag gid: 'V-254948'
  tag rid: 'SV-254948r867744_rule'
  tag stig_id: 'TANS-AP-001150'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-58505r867743_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
