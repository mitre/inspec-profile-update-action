control 'SV-77551' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x On-Demand scan must be configured to scan mounted volumes when mounted volumes point to a network server without an anti-virus solution installed.'
  desc 'A server that functions as an attached disk drive is vulnerable if it is internally unprotected. Network attached storage (NAS) devices often have poor security. If they do not require any authentication, any infected device on the local network can grab confidential data from them or plant malicious files. To guard against malware on the network level, all devices must be taken into account. Any unprotected machine is a weakness for the whole network. It is imperative to protect Linux systems from malware introduced from mounted volumes pointing to network servers without an antivirus solution by ensuring they are scanned.'
  desc 'check', %q(With the System Administrator's assistance, determine network mounted volumes on the Linux system being reviewed. If network mounted volumes are mounted, verify whether anti-virus protection is locally installed and configured to protect the network servers to which the mounted volumes connect.

If all network servers to which mounted volumes connect are protected by locally installed and configured anti-virus protection, this check for the Linux system being reviewed is Not Applicable.

If no network mounted volumes are configured on the Linux system being reviewed, this check is Not Applicable.

If mounted volumes exist on the Linux system being reviewed which are connecting to network servers which lack locally installed and configured anti-virus protection, this check must be validated.

From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page.

Click on Actions >> Agent >> Modify Tasks on a Single System.

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task.

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.
In the "Where" tab, in the "Specify where scanning will take place", verify all otherwise unprotected network servers to which this Linux system has mounted volumes have been included.

If the "Specify where scanning will take place" does not have all otherwise unprotected network servers to which this Linux system has mounted volumes included, this is a finding.)
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page.

Click on Actions >> Agent >> Modify Tasks on a Single System.

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the weekly On Demand scan client task.

If a weekly On Demand scan client task does not exist, this is a finding.

For the designated weekly On Demand scan client task, verify the "Task Type" is listed as "On Demand Scan".
Verify the "Status" is listed as "Enabled".
Under the "Task Name" column, click on the link for the designated task to review the task properties.

In the "Where" tab, in the "Specify where scanning will take place", verify the all otherwise unprotected network servers to which this Linux system has mounted volumes is included.'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63061'
  tag rid: 'SV-77551r2_rule'
  tag stig_id: 'DTAVSEL-114'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-68979r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
