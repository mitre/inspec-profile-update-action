control 'SV-16781' do
  title 'ESX Server does not record log files.'
  desc 'Logs form a recorded history or audit trail of the ESX Server system events, making it easier for system administrators to track down intermittent problems, review past events, and piece together information if an investigation is required.  Without this recorded history, potential attacks and suspicious activity will go unnoticed.  

ESX Server log files that are critical to record include VMkernel, VMkernel warnings, VMkernel summary, ESX Server host agent, virtual machines,  VI Client agent,Web Access, service console, and authentication. The VMkernel logs record activities related to the virtual machines and the ESX Server. The VMkernel warning log file records activities with the virtual machines. The VMkernel summary is used to determine uptime and availability statistics for the ESX Server. The ESX Server host agent log contains information on the agent that manages and configures the ESX Server host. This log may assist in diagnosing connection problems.  The virtual machine log files contain information when a virtual machine crashes or shutdowns abnormally. The VI Client agent is installed on each managed ESX Server and this log records all the activities of the agent. Web Access records information on web-based access to the ESX Server.  This is important to view since web-based access to the ESX Server should be disabled. The service console messages contain all general log messages used to troubleshoot virtual machines or the ESX Server. The authentication log contains records of connections that require authentication.'
  desc 'check', 'To verify that all the log files are being written to, perform the following on the ESX Server service console:
# ls –l /var/log | awk ‘{if ($5 ~ /^0$/) print}’

If any of the following log files are returned, this is a finding.  
vmkernel
vmkwarning
vmksummary.txt
messages
secure

# ls –l /var/log/vmware/ | awk ‘{if ($5 ~ /^0$/) print}’

If any of the following log files are returned, this is a finding.  
vpxa.log
webAccess

Work with SA to locate the path to the virtual machines.
# ls –l  <virtual machine path on ESX>/   | awk ‘{if ($5 ~ /^0$/) print}’

If the following log file is returned, this is a finding.  
vmware.log

Caveat: If logs are being sent to a syslog server, then work with the system administrator to verify they are being written to.

Location of all logs to be verified are listed below:

VMkernel
	/var/log/vmkernel 
VMkernel warnings:
	/var/log/vmkwarning 
VMkernel summary:
	/var/log/vmksummary.txt
ESX Server host agent log:
	/var/log/vmware/hostd.log 
Individual virtual machine logs:
	<path to virtual machine on ESX Server>/vmware.log
VI Client agent log:
	/var/log/vmware/vpx/vpxa.log
Web access:
	/var/log/vmware/webAccess
Service console:
	/var/log/messages 
Authentication log:
	/var/log/secure'
  desc 'fix', 'Record all critical log files on the ESX Server.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16186r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15840'
  tag rid: 'SV-16781r1_rule'
  tag stig_id: 'ESX0410'
  tag gtitle: 'ESX Server does not record log files.'
  tag fix_id: 'F-15794r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
