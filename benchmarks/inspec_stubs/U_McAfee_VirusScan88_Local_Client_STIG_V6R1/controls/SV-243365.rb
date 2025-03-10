control 'SV-243365' do
  title 'McAfee VirusScan must be configured to receive DAT and Engine updates.'
  desc 'Antivirus signature files are updated almost daily by antivirus software vendors. These files are made available to antivirus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. The antivirus software product must be configured to receive those updates automatically in order to afford the expected protection.'
  desc 'check', 'NOTE: Automatic updates to antivirus signature definitions are to be performed once every 24 hours for hosts connected to the network. Hosts not connected to the network must be updated manually. 

Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.

Under the "Task" column, right-click on the "AutoUpdate" option, select "Properties".
Click the "Schedule" button.
On the "Task" tab, the selection for "Enable (scheduled task runs at specified time)" must be selected.
On the "Schedule" tab, the "Run task:" option must be configured with "Daily".

Alternative Registry method:
Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\McAfee for 32-bit systems
HKLM\\Software\\Wow6432Node\\McAfee for 64-bit systems
\\DesktopProtection\\Tasks\\{A14CD6FC-3BA8-4703-87BF-e3247CE382F5}

Criteria: 
If "bSchedEnabled=1" (indicates Scheduling is enabled) and "eScheduleType=0" (indicates Daily), this is not a finding. 

If "bSchedEnabled=0" (indicates Scheduling is not enabled), this is a finding.

If the "AutoUpdate" task schedule is not enabled, or is not configured to run at a frequency of "Daily", this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.

Under the Task column, find the AutoUpdate option, right-click, and choose Properties.
Click the Schedule button.
On the Task tab, select "Enable (scheduled task runs at specified time)".
On the Schedule tab, the "Run task:" option must be configured with Daily.

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46640r722671_chk'
  tag severity: 'medium'
  tag gid: 'V-243365'
  tag rid: 'SV-243365r722672_rule'
  tag stig_id: 'DTAM016'
  tag gtitle: 'SRG-APP-000272'
  tag fix_id: 'F-46597r722433_fix'
  tag 'documentable'
  tag legacy: ['V-6591', 'SV-56390']
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
