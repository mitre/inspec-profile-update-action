control 'SV-207694' do
  title 'The Palo Alto Networks security platform must install updates for application software files, signature definitions, detection heuristics, and vendor-provided rules when new releases are available in accordance with organizational configuration management policy and procedures.'
  desc 'Failing to update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs.

The IDPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, IDPS components must be updated, including application software files, anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures.

Updates must be installed in accordance with the CCB procedures for the local organization. However, at a minimum:
Updates designated as critical security updates by the vendor must be installed immediately.
Updates for signature definitions, detection heuristics, and vendor-provided rules must be installed immediately.
Updates for application software are installed in accordance with the CCB procedures.
Prior to automatically installing updates, either manual or automated integrity and authentication checking is required, at a minimum, for application software updates.'
  desc 'check', 'Since some networks cannot connect to the vendor site for automatic updates, a manual process can be used.

To verify that the  Palo Alto Networks security platform is using the current Applications and Threats database should be checked by viewing the Dashboard and the version and date compared to the latest release.
Go to Dashboard; in the General Information pane, view the Threat Version and Antivirus Version.  If they are not the most current version as listed on the Palo Alto Networks support site, this is a finding.

The following check applies if the network is authorized to connect to the Vendor site for automatic updates.
To verify that automatic updates are configured,
Go to Device >> Dynamic Updates
If no entries for "Applications and Threats" are present, this is a finding.  
If the "Applications and Threats" entry states "Download Only", this is a finding.'
  desc 'fix', 'Go to Device >> Dynamic Updates
Select "Check Now" at the bottom of the page to retrieve the latest signatures.
To schedule automatic signature updates.  
Note: the steps provided below do not account for local change management policies.

Go to Device >> Dynamic Updates
Select the text to the right of "Schedule".
In the "Applications and Threat Updates Schedule" window; complete the required information.  
In the "Recurrence" field, select "Daily".
In the "Time" field, enter the time at which you want the device to check for updates.
For the "Action", select "Download and Install".   
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.
 
If manual updates are used, an Administrator must obtain updates from the Palo Alto Networks support site and upload them from a workstation or server to the Palo Alto Networks security platform.
Go to Device >> Dynamic Updates
Select "Upload" (at the bottom of the pane).
In the "Select Package Type for the Upload" window in the "Package Type" field, select "anti-virus".
Browse to and select the appropriate file.
Select "OK".

Select "Install From File" (at the bottom of the pane).
In the "Select Package Type for Installation" window, select "antivirus".
Select "OK".

In the "Install Application and Threats From File" window, select the previously uploaded file.
Select "OK".'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7948r358415_chk'
  tag severity: 'medium'
  tag gid: 'V-207694'
  tag rid: 'SV-207694r557390_rule'
  tag stig_id: 'PANW-IP-000024'
  tag gtitle: 'SRG-NET-000246-IDPS-00205'
  tag fix_id: 'F-7948r358416_fix'
  tag 'documentable'
  tag legacy: ['SV-77149', 'V-62659']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
