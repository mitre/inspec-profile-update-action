control 'SV-254920' do
  title 'The Tanium application must manage bandwidth throttles to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

In the case of application DoS attacks, care must be taken when designing the application to ensure the application makes the best use of system resources. SQL queries have the potential to consume large amounts of CPU cycles if they are not tuned for optimal performance. Web services containing complex calculations requiring large amounts of time to complete can bog down if too many requests for the service are encountered within a short period of time. 

The methods employed to meet this requirement will vary depending upon the technology the application utilizes. However, a variety of technologies exist to limit or, in some cases, eliminate the effects of application related DoS attacks. Employing increased capacity and bandwidth combined with specialized application layer protection devices and service redundancy may reduce the susceptibility to some DoS attacks.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.  

2. Click "Administration" on the top navigation banner.  

3. Under "Configuration," select "Bandwidth Throttles".  

4. Work with the Tanium Administrator to confirm settings.   

5. If bandwidth throttles are not configured, this is a finding. For more information, see the following: https://docs.tanium.com/platform_user/platform_user/console_bandwidth_throttling.html.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration," select "Bandwidth Throttles".

4. Click "Add" on the line for "Global Throttle for All Data".

5. Work with Tanium Administrator to configure the required bandwidth throttles.

6. Click "Save".

7. Work with the Tanium Administrator to confirm or set settings for the remaining options:

7A. Global Throttle for Package Files.

7B. Global Throttle for Sensors.

7C. Site Throttles.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58533r867658_chk'
  tag severity: 'medium'
  tag gid: 'V-254920'
  tag rid: 'SV-254920r867660_rule'
  tag stig_id: 'TANS-AP-000635'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-58477r867659_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
