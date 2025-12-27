control 'SV-16782' do
  title 'ESX Server log files are not reviewed daily.'
  desc 'Logs form a recorded history or audit trail of the ESX Server system events, making it easier for system administrators to track down intermittent problems, review past events, and piece together information if an investigation is required.  Without this recorded history, potential attacks and suspicious activity will go unnoticed.  

ESX Server log files that are critical to record include VMkernel, VMkernel warnings, VMkernel summary, ESX Server host agent, virtual machines,  VI Client agent,Web Access, service console, and authentication. The VMkernel logs record activities related to the virtual machines and the ESX Server. The VMkernel warning log file records activities with the virtual machines. The VMkernel summary is used to determine uptime and availability statistics for the ESX Server. The ESX Server host agent log contains information on the agent that manages and configures the ESX Server host. This log may assist in diagnosing connection problems.  The virtual machine log files contain information when a virtual machine crashes or shutdowns abnormally. The VI Client agent is installed on each managed ESX Server and this log records all the activities of the agent. Web Access records information on web-based access to the ESX Server.  This is important to view since web-based access to the ESX Server should be disabled. The service console messages contain all general log messages used to troubleshoot virtual machines or the ESX Server. The authentication log contains records of connections that require authentication.'
  desc 'check', 'Ask the IAO/SA how often they review the ESX Server log files listed below:

VMkernel
	/var/log/vmkernel,
VMkernel warnings:
	/var/log/vmkwarning,
VMkernel summary:
	/var/log/vmksummary.txt,
ESX Server host agent log:
	/var/log/vmware/hostd.log, 
Individual virtual machine logs:
	<path to virtual machine on ESX, Server>/vmware.log
VI Client agent log:
	/var/log/vmware/vpx/vpxa.log,
Web access:
	/var/log/vmware/webAccess,
Service console:
	/var/log/messages, 
Authentication log:
	/var/log/secure.

Caveat: If the log files are being written to a syslog server, work with the system administrator to verify they are being reviewed there.

If the IAO/SA does not review them daily, this is a finding.'
  desc 'fix', 'Review ESX Server log files daily.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15841'
  tag rid: 'SV-16782r1_rule'
  tag stig_id: 'ESX0420'
  tag gtitle: 'ESX Server log files are not reviewed daily'
  tag fix_id: 'F-15795r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECAT-1, ECAT-2'
end
