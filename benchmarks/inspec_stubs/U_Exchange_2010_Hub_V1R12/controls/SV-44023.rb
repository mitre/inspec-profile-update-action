control 'SV-44023' do
  title 'Exchange must not send auto replies to remote domains.'
  desc "Attackers can use automated messages to determine whether a user account is active, in the office, traveling, and so on. An attacker might use this information to conduct future attacks. Remote users will not receive automated 'Out Of Office' delivery reports. This setting can be used to determine if all the servers in the Organization can send 'Out of Office' messages."
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain | select identity, AutoReplyEnabled

If the value of 'AutoReplyEnabled' is not set to 'False', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'RemoteDomainName'> -AutoReplyEnabled $false"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41711r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33603'
  tag rid: 'SV-44023r1_rule'
  tag stig_id: 'Exch-2-814'
  tag gtitle: 'Exch-2-814'
  tag fix_id: 'F-37496r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
