control 'SV-16784' do
  title 'ESX Server does not send logs to a syslog server.'
  desc 'Remote logging is essential in detecting intrusion and monitoring servers. If an intruder is able to obtain root on a host, they may be able to edit the system logs to remove all traces of the attack.  If the logs are stored off the machine, those logs can be analyzed for suspicious activity and used for prosecuting the attacker. Centralized log monitoring and storage is a critical component of incident response and assuring the integrity of system logs.

Redundancy is important when considering using a virtual machine for a syslog server.  If the syslog virtual machine is hosted on only one ESX Server, and the ESX Server fails, all logging to the syslog server will cease. Configuring the syslog server as a virtual machine requires proper failover planning in case the primary ESX Server would fail. To mitigate this scenario, syslog virtual machines will be configured within ESX Server farms with High Availability (HA) enabled.'
  desc 'check', '1. To determine is the ESX Server is sending its logs to a remote syslog server, examine the /etc/syslog.conf file on the ESX Server service console.  
2. To send all syslog data from the ESX Server to a remote syslog host, search for the following line(s) in the /etc/syslog.conf file:
*.* <Tab><Tab> @loghost (name of remote host)
Or
*.debug, info, etc.@loghost.

At a minimum, the following log files should be configured to send logs to the syslog server:

Log Name				Facility.Level			Default Location
Service Console Logs	*.info	 		/var/log/messages
Authentication Logs		Authpriv.*		/var/log/secure
VMkernel Logs			Local6.notice		/var/log/vmkernel
VMkernel Warnings		Local6.warning		/var/log/vmkwarning

If these are not configured to the syslog server, this is a finding.

3. Verify the loghost referred to in the syslog.conf file is not resolving to the localhost.  Check /etc/hosts file to review what the remote host is referring to. If it is not in this file, check the DNS server to determine what it is resolving to. If it is resolving to localhost, this is a finding.  

Caveat: This syslog server may be a virtual machine within an ESX Server farm with HA enabled.  If the syslog server is a virtual machine within a server farm and HA is not enabled, this is a finding. It may not be a virtual machine if there is only one ESX Server for the site. If this is the case, this is a finding.'
  desc 'fix', 'Configure the ESX Server to send all its logs to a syslog server.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16189r1_chk'
  tag severity: 'low'
  tag gid: 'V-15843'
  tag rid: 'SV-16784r1_rule'
  tag stig_id: 'ESX0440'
  tag gtitle: 'ESX Server does not send logs to syslog server.'
  tag fix_id: 'F-15797r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
