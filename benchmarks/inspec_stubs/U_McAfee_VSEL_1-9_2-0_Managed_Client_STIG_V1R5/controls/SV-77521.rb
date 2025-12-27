control 'SV-77521' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Access scanner must be enabled to scan mounted volumes when mounted volumes point to a network server without an anti-virus solution installed.'
  desc 'Mounting network volumes to other network systems introduces a path for malware to be introduced. It is imperative to protect Linux systems from malware introduced from those other network systems by either ensuring the remote systems are protected or by scanning files from those systems when they are accessed.'
  desc 'check', %q(With the System Administrator's assistance, determine network mounted volumes on the Linux system being reviewed. 

If network mounted volumes are mounted, verify whether anti-virus protection is locally installed on, and configured to protect, the network servers to which the mounted volumes connect.

If all network servers to which mounted volumes connect are protected by locally installed and configured anti-virus protection, this check for the Linux system being reviewed is Not Applicable. 

If no network mounted volumes are configured on the Linux system being reviewed, this check is Not Applicable.

If mounted volumes exist on the Linux system being reviewed which are connecting to network servers which lack locally installed and configured anti-virus protection, this check must be validated.

From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page.

Click on Actions >> Agent >> Modify Policies on a Single System.
From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".
From the "Policy" column, click on the policy for the "On-Access Scanning Policy"
In the "Detections" tab, next to "Scan files:", verify the check box for "On network mounted volumes" is selected.

If the check box for "On network mounted volumes" is not selected, this is a finding.)
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 

Click on Actions >> Agent >> Modify Policies on a Single System.
From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".
From the "Policy" column, click on the policy for the "On-Access Scanning Policy".
In the "Detections" tab, next to "Scan files:", select the check box for "On network mounted volume".

Click "Apply".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63031'
  tag rid: 'SV-77521r1_rule'
  tag stig_id: 'DTAVSEL-019'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-68949r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
