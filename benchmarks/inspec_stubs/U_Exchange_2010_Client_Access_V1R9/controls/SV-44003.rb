control 'SV-44003' do
  title 'Web email must use standard ports  protocols.'
  desc 'PPSM standard defined ports and protocols must be used for all Exchange services.  The standard port for HTTP connections is 80 and the standard port for HTTPS
connections is 443.  

Changing the ports to non-standard values provides only temporary and limited protection against automated attacks since these attacks will not likely connect to the custom port.  However, a determined attacker may still be able to determine which ports are used for the HTTP and HTTPS protocols by performing a comprehensive port scan.  

Negative impacts to using nonstandard ports include complexity for the system administrator, custom configurations for connecting clients, risk of port conflict with non-exchange applications, and risk of incompatibility with standard port monitoring applications.'
  desc 'check', "Open a Windows PowerShell Module and enter the following command:

Get-WebBinding -Name <'WebSiteName'>| Format-List

If the Web binding values are not on standard port 80 for HTTP connections or port 443 for HTTPS connections, this is a finding."
  desc 'fix', 'Configure web ports to be port 80 and 443, as specified by PPSM standards.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41690r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33584'
  tag rid: 'SV-44003r1_rule'
  tag stig_id: 'Exch-1-202'
  tag gtitle: 'Exch-1-202'
  tag fix_id: 'F-37475r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
