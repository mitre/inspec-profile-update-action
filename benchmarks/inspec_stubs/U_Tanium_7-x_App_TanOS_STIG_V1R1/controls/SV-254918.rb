control 'SV-254918' do
  title 'The Tanium Server and Client applications must have logging enabled.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'Tanium Server:

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Administration" on the top navigation banner. 

3. Under "Configuration," select "Common".

4. Select "Log Level".

5. In "Log Verbosity Level for Troubleshooting," verify current level for "Tanium Server" is set.

If the value for current level for "Tanium Server" is not set to "1" or higher this is a finding.

Tanium Client:

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top navigation banner.

3. Click "Interact".

4. In the "Explore Data" box, type the following question:

4A. Get Tanium Client Explicit Setting[LogVerbosityLevel] < 1 and Is Windows from all machines with Tanium Client Explicit Setting[LogVerbosityLevel] < 1

Note: For VDI systems, follow vendor guidance: https://docs.tanium.com/client/client/os_imaging.html#VDI

If there are any answers returned that are "0" this is a finding.'
  desc 'fix', 'Tanium Server:

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Administration" on the top navigation banner. 

3. Under "Configuration," select "Common".

4. Select "Log Level".

5. In "Log Verbosity Level for Troubleshooting," verify current level for "Tanium Server" is set.

Tanium Client:

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top navigation banner.

3. Click "Interact".

4. In the "Explore Data" box, type the following question:
4A. Get Tanium Client Explicit Setting[LogVerbosityLevel] < 1 and Is Windows from all machines with Tanium Client Explicit Setting[LogVerbosityLevel] < 1

5. Select the row with "Is windows" set to "True" and deploy the following action and settings:
   a) Deployment Package: Modify Tanium Client Setting
    b) RegType: REG_DWORD
    c) ValueName: LogVerbosityLevel
    d) ValueData: 1 or higher
    
    Schedule Deployment
    a) Distribute over: 1 hour

6. Click "Show Preview to continue".

7. Click "Deploy Action".

8. Select the row with "Is windows" set to "False" and deploy the following action and settings:
    a) Deployment Package: Modify Tanium Client Setting [Non-Windows]
    b) RegType: NUMERIC
    c) ValueName: LogVerbosityLevel
    d) ValueData: 1 or higher
    
    Schedule Deployment
    a) Distribute over: 1 hour

9. Click "Show Preview to continue".

10. Click "Deploy Action".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58531r867652_chk'
  tag severity: 'medium'
  tag gid: 'V-254918'
  tag rid: 'SV-254918r867654_rule'
  tag stig_id: 'TANS-AP-000600'
  tag gtitle: 'SRG-APP-000226'
  tag fix_id: 'F-58475r867653_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
