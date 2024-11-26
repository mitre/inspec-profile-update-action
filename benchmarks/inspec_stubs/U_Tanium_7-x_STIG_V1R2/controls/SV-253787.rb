control 'SV-253787' do
  title 'The Tanium application must manage bandwidth throttles to limit the effects of information flooding types of denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

In the case of application DoS attacks, care must be taken when designing the application to ensure the application makes the best use of system resources. SQL queries have the potential to consume large amounts of CPU cycles if they are not tuned for optimal performance. Web services containing complex calculations requiring large amounts of time to complete can bog down if too many requests for the service are encountered within a short period of time. 

The methods employed to meet this requirement will vary depending on the technology the application uses. However, a variety of technologies exist to limit or, in some cases, eliminate the effects of application-related DoS attacks. Employing increased capacity and bandwidth combined with specialized application layer protection devices and service redundancy may reduce the susceptibility to some DoS attacks.'
  desc 'check', %q(1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Bandwidth Throttles".

4. Work with the Tanium administrator to confirm settings. 

For more information, refer to https://docs.tanium.com/platform_user/platform_user/console_bandwidth_throttling.html.

If the Bandwidth Throttles configuration is not accordance with organization's needs, this is a finding.)
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Bandwidth Throttles".

4. Click "Add" on the line for "Global Throttle for All Data".

5. Work with the Tanium administrator to configure the required bandwidth throttles.

6. Click "Save".

7. Work with the Tanium administrator to confirm or set the remaining options:

 - Global Throttle for Package Files.
 - Global Throttle for Sensors.
 - Site Throttles.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57239r842387_chk'
  tag severity: 'medium'
  tag gid: 'V-253787'
  tag rid: 'SV-253787r842389_rule'
  tag stig_id: 'TANS-00-001170'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-57190r842388_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
