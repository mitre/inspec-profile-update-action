control 'SV-207318' do
  title 'Exchange must not send automated replies to remote domains.'
  desc 'Attackers can use automated messages to determine whether a user account is active, in the office, traveling, and so on. An attacker might use this information to conduct future attacks. Remote users will not receive automated "Out Of Office" delivery reports. This setting can be used to determine if all the servers in the Organization can send "Out of Office" messages.'
  desc 'check', 'Note: Automated replies to .MIL or .GOV sites are allowed.
Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain | Select Name, Identity, AutoReplyEnabled
If the value of “AutoReplyEnabled” is set to “True” and is configured to only Reply to .MIL or .GOV sites, this is not a finding.

If the value of AutoReplyEnabled is not set to False, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'IdentityName'> -AutoReplyEnabled $false

Note: The <IdentityName> value must be in quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7576r393467_chk'
  tag severity: 'medium'
  tag gid: 'V-207318'
  tag rid: 'SV-207318r615936_rule'
  tag stig_id: 'EX13-MB-000260'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-7576r393468_fix'
  tag 'documentable'
  tag legacy: ['SV-84665', 'V-70043']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
