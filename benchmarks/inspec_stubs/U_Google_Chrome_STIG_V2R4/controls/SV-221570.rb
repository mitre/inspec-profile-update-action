control 'SV-221570' do
  title 'Background processing must be disabled.'
  desc "Determines whether a Google Chrome process is started on OS login that keeps running when the last browser window is closed, allowing background apps to remain active. The background process displays an icon in the system tray and can always be closed from there. If this policy is set to True, background mode is enabled and cannot be controlled by the user in the browser settings. If this policy is set to False, background mode is disabled and cannot be controlled by the user in the browser settings. If this policy is left unset, background mode is initially disabled and can be controlled by the user in the browser settings.' - Google Chrome Administrators Policy ListThis setting, if enabled, allows Google Chrome to run at all times. There is two reasons that this is not wanted. First, it can tie up system resources that might otherwise be needed. Second, it does not make it obvious to the user that it is running and poorly written extensions could cause instability on the system."
  desc 'check', 'Universal method:        
   1. In the omnibox (address bar) type chrome://policy        
   2. If BackgroundModeEnabled is not displayed under the Policy Name column and it is not set to false under the Policy Value column, then this is a finding.

Windows method:
   1. Start regedit
   2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
   3. If the BackgroundModeEnabled value name does not exist or its value data is not set to 0, then this is a finding.'
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
    Policy Name: Continue running background apps when Google Chrome is closed
    Policy State: Disabled
    Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23285r415837_chk'
  tag severity: 'medium'
  tag gid: 'V-221570'
  tag rid: 'SV-221570r615937_rule'
  tag stig_id: 'DTBC-0017'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-23274r415838_fix'
  tag 'documentable'
  tag legacy: ['SV-57587', 'V-44753']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
