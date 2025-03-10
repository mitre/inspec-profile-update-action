control 'SV-221642' do
  title 'The Workspace ONE UEM server must be configured with a periodicity for reachable events of six hours or less for the following commands to the agent: 
- query connectivity status;
- query the current version of the MD firmware/software;
- query the current version of installed mobile applications;
- read audit logs kept by the MD.'
  desc 'Key security-related status attributes must be queried frequently so the Workspace ONE UEM server can report status of devices under management to the administrator and management. The periodicity of these queries must be configured to an acceptable timeframe. Six hours or less is considered acceptable for normal operations.

SFR ID: FMT_SMF.1.1(2) c.3'
  desc 'check', 'Review the Workspace ONE UEM server for a periodicity for reachable events of six hours or less for the following commands to the agent: 
- query connectivity status;
- query the current version of the MD firmware/software;
- query the current version of installed mobile applications.

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Navigate to Groups & Settings >> All Settings.
3. Under the "Devices & Users" heading:

For Android, choose Android >> Intelligent Hub Settings.
a. Under the General heading, if "Heartbeat Interval" is set to more than six hours, this is a finding. This setting handles querying of connectivity status and current version of MD firmware/software.
b. Under the Application List heading, if the "Application List Interval" is set to more than 360 minutes, this is a finding. This setting handles querying for current version of installed mobile applications.

For iOS, Apple >> MDM Sample Schedule.
a. If "Device Information Sample" is set to more than six hours, this is a finding. This setting handles querying of connectivity status and current version of MD firmware/software.
b. If "Application List Sample" and "Managed App List Sample" are set to more than 6 hours, this is a finding. This setting handles querying for current version of installed mobile applications.'
  desc 'fix', 'Configure the Workspace ONE UEM server with a periodicity for reachable events of six hours or less for the following commands to the agent:
- query connectivity status;
- query the current version of the MD firmware/software;
- query the current version of installed mobile applications.

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Navigate to Groups & Settings >> All Settings.
3. Under the "Devices & Users" heading:

For Android, choose Android >> Intelligent Hub Settings. To modify any settings, click "Override".
a. Under the General heading, set "Heartbeat Interval" using the drop-down if necessary. This setting handles querying of connectivity status and current version of MD firmware/software.
b. Under the Application List heading, set the "Application List Interval" as necessary to the appropriate number of minutes.
c. There is no control for periodicity of reading audit logs. They are sent to the server automatically.

For iOS, choose Apple >> MDM Sample Schedule. To modify any settings, click "Override".
a. Set "Device Information Sample" as necessary to the appropriate number of hours. This will control periodicity of both querying connectivity and querying the current version of MD firmware/software.
b. Querying of installed mobile applications is controlled by both "Application List Sample" and "Managed App List Sample" fields. Application List Sample requests all the apps on the device (managed and unmanaged), whereas Managed App List Sample only returns MDM installed apps. Both samples return app versions.
c. There is no control for periodicity of reading audit logs. They are sent to the server automatically.'
  impact 0.5
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23357r416764_chk'
  tag severity: 'medium'
  tag gid: 'V-221642'
  tag rid: 'SV-221642r588007_rule'
  tag stig_id: 'VMW1-00-000540'
  tag gtitle: 'PP-MDM-411057'
  tag fix_id: 'F-23346r416765_fix'
  tag 'documentable'
  tag legacy: ['SV-111283', 'V-102327']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
