control 'SV-77469' do
  title 'Riverbed Optimization System (RiOS) performing maintenance functions must restrict use of these functions to authorized personnel only.'
  desc 'There are security-related issues arising from software brought into the network device specifically for diagnostic and repair actions (e.g., a software packet sniffer installed on a device in order to troubleshoot system traffic, or a vendor installing or running a diagnostic application in order to troubleshoot an issue with a vendor-supported device). If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system.

This requirement addresses security-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational network devices. Maintenance tools can include hardware, software, and firmware items. Maintenance tools are potential vehicles for transporting malicious code, either intentionally or unintentionally, into a facility and subsequently into organizational information systems. Maintenance tools can include, for example, hardware/software diagnostic test equipment and hardware/software packet sniffers. This requirement does not cover hardware/software components that may support information system maintenance yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'Verify that RiOS is configured so that performing maintenance functions is restricted to authorized personnel only.

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Verify that only authorized personnel have the permissions to perform maintenance functions

If user permissions for authorized personnel are not set to authorize maintenance functions, this is a finding.'
  desc 'fix', 'Configure RiOS to restrict use of maintenance functions to authorized personnel only.

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions
Click "Add New User Account" under "Role Based Accounts"
Set User Permissions of authorized personnel to allow performance of maintenance functions
Click "Add"

Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63731r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62979'
  tag rid: 'SV-77469r1_rule'
  tag stig_id: 'RICX-DM-000133'
  tag gtitle: 'SRG-APP-000408-NDM-000314'
  tag fix_id: 'F-68897r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002883']
  tag nist: ['CM-6 b', 'MA-3 (4)']
end
