control 'SV-228847' do
  title 'The Palo Alto Networks security platform must update malicious code protection mechanisms and signature definitions whenever new releases are available in accordance with organizational configuration management policy and procedures.'
  desc 'In order to minimize any potential negative impact to the organization caused by malicious code, malicious code must be identified and eradicated. Malicious code includes viruses, worms, Trojan horses, and Spyware.'
  desc 'check', 'Check if the device is using the most current protection mechanisms and signature definitions.
If the device has authorized connectivity to the Palo Alto site, the automated process can be used.
Go to Device >> Dynamic Updates
View the list of updates, and note the date of the most recent one.
Select "Check Now" at the bottom of the page; if new updates appear, this is a finding.
If the device does not have connectivity to the Palo Alto site, a manual process must be used.
Log on to the Palo Alto Support site (registration required).
Select the “Dynamic Updates” hyperlink.
Check for the most current update (the version and release date of each update is listed).
Go to Device >> Dynamic Updates
View the list of updates and note the date of the most recent one.
If the device does not have the most current updates installed, this is a finding.'
  desc 'fix', 'If the device has authorized connectivity to the Palo Alto site, automatic updates can be used.

To schedule automatic updates:
Go to Device >> Dynamic Updates
Select the text to the right of Schedule.
In the "Applications and Threat Updates Schedule" Window; complete the required information. 
In the "Recurrence" field, select the desired frequency. If the update frequency is Weekly, select which day of the week. 
In the "Time" field, enter the time at which you want the device to check for updates.
For the Action, select "Download and Install". 
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.

To retrieve the latest signatures:
Go to Device >> Dynamic Updates
Select "Check Now" at the bottom of the page.  

If the device does not have authorized connectivity to the Palo Alto site, a manual process must be used. If manual updates are used, an Administrator must obtain updates from the Palo Alto Networks website and upload them from a workstation or server to the device.
Go to Device >> Dynamic Updates
Select "Upload" (at the bottom of the pane).
In the Select "Package Type" for the "Upload" window in the "Package Type" field, select "anti-virus".
Browse to and select the appropriate file.
Select "OK".
Select "Install From File" (at the bottom of the pane).
In the "Select Package Type for Installation" window, select "antivirus".
Select "OK".
In the "Install Application and Threats From File" window, select the previously uploaded file.
Select "OK".'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31082r513836_chk'
  tag severity: 'medium'
  tag gid: 'V-228847'
  tag rid: 'SV-228847r557387_rule'
  tag stig_id: 'PANW-AG-000060'
  tag gtitle: 'SRG-NET-000246-ALG-000132'
  tag fix_id: 'F-31059r513837_fix'
  tag 'documentable'
  tag legacy: ['SV-77067', 'V-62577']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
