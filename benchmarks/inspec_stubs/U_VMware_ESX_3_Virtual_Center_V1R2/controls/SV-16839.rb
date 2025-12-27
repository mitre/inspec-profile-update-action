control 'SV-16839' do
  title 'Virtual machines are not time synchronized with the ESX Server or an authoritative time server.'
  desc 'The accuracy of time within the virtualization environment is difficult due to the timer interrupt issue. Time drifts may be as dramatic as 5-10 minutes. Inaccurate time causes other inaccuracies within the virtualization environment, which may include event logs, domain synchronization, session timeouts, etc. Virtual machine time synchronization may be achieved through an external time source or through the ESX Server operating system.'
  desc 'check', '1. Ask the IAO/SA how virtual machines are time synchronized.  If they synchronized to an external server, then go to step 2.  If configured to the ESX Server host,  go to step 3.
2. Time servers are configured in the /etc/ntp.conf file on UNIX systems. Once they are configured with an atomic clock, the ntpd daemon should be configured to start at the runlevels 3, 4, and 5.  Windows servers are configured via the command line using the net time /setsntp:clock.isc.org.  The w32time service will need to be configured to start after the change.

Unix Systems: 
# less /etc/ntp.conf 

Verify a valid time server is listed.  If not, this is a finding.

Windows systems:
Start, run, cmd
C:\\>net time /querysntp 

If no results are displayed to use a valid SNTP server, this is a finding.   

3. Login to VirtualCenter with the VI Client and select a virtual machine from the Inventory panel.
4. Click the Edit Settings link in the Commands panel.
The Virtual Machine Properties dialog box is displayed.  Select the Options tab.
5. Select VMware Tools in the Settings list.
6. Verify the guest operating system is configured to synchronize time with the host ESX Server.  This is enabled when the “Synchronize guest time with host” option is checked.  If it is not checked, then this is a finding.'
  desc 'fix', 'Synchronize the virtual machine with an external time source or the ESX Server host.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16257r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15897'
  tag rid: 'SV-16839r1_rule'
  tag stig_id: 'ESX1010'
  tag gtitle: 'Virtual machines are not time synchronized'
  tag fix_id: 'F-15858r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
