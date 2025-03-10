control 'SV-44042' do
  title 'Accepted domains must be configured.'
  desc 'Exchange may be configured to accept email for multiple domain names. This setting identifies the domains for which the server will accept mail. This check verifies the email server is not accepting email for unauthorized domains.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the 'Accepted Domain' values.  

Open the Exchange Management Shell and enter the following command:
 
Get-AcceptedDomain

If the value for 'AcceptedDomains' is not set to the value in the EDSP, this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:
 
Set-AcceptedDomain -Identity <'ValueInEDSP'> -MakeDefault $true"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41729r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33622'
  tag rid: 'SV-44042r1_rule'
  tag stig_id: 'Exch-2-005'
  tag gtitle: 'Exch-2-005'
  tag fix_id: 'F-37514r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
