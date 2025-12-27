control 'SV-77491' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be configured to decompress archives when scanning.'
  desc 'Malware is often packaged within an archive. In addition, archives may have other archives within. Not scanning archive files introduces the risk of infected files being introduced into the environment.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. 

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System. 

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x". From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Advanced" tab, next to the "Compressed files", verify the check box for "Scan inside multiple-file archives (e.g., .ZIP)" is selected.

If the check box for "Compressed files: Scan inside multiple-file archives (e.g., .ZIP)" is not selected, this is a finding. 

SECURITY OVERRIDE:
If the check box for "Compressed files: Scan inside multiple-file archives (e.g., .ZIP)" is not selected but the On-Demand scan decompress of archives is configured in the regularly scheduled scan, as specified in STIG ID DTAVSEL-101, this is a finding but can be dropped to a CAT III.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. 

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".

From the "Policy" column, click on the policy for the "On-Access Scanning Policy".

In the "Advanced" tab, next to the "Compressed files", select the check box for "Scan inside multiple-file archives (e.g., .ZIP)".

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63753r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63001'
  tag rid: 'SV-77491r1_rule'
  tag stig_id: 'DTAVSEL-004'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-68919r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
