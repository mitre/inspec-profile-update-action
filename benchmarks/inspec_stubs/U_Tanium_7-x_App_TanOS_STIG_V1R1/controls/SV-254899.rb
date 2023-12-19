control 'SV-254899' do
  title 'The Tanium application must be configured to send audit records from multiple components within the system to a central location for review and analysis of audit records.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis to allow the organization to identify and respond to potential incidents in a proficient manner. If the application does not provide the ability to centrally review the application logs, forensic analysis is negatively impacted.

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system or application has multiple logging components written to different locations or systems.

Automated mechanisms for centralized reviews and analyses include, for example, Security Information Management products.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Review the configured Connections under the "Connections" section.

If no Connection exists to send the "Tanium Audit Source" to a SIEM tool, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Click "Create Connection".

5. In the "Configuration" section under "Source," select "Tanium Audit Source" as the source from the drop-down menu.

6. In the "Configuration" section under "Destination," select the desired Destination and fill in the respective fields.

7. In the "Configure Output" section under "Format," select the desired file format type.

8. In the "Schedule" section, select the desired schedule.

9. Click "Create Connection".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58512r870360_chk'
  tag severity: 'medium'
  tag gid: 'V-254899'
  tag rid: 'SV-254899r870360_rule'
  tag stig_id: 'TANS-AP-000270'
  tag gtitle: 'SRG-APP-000111'
  tag fix_id: 'F-58456r867596_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
