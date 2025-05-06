control 'SV-228396' do
  title 'Exchange must not send automated replies to remote domains.'
  desc 'Attackers can use automated messages to determine whether a user account is active, in the office, traveling, and so on. An attacker might use this information to conduct future attacks. Remote users will not receive automated "Out of Office" delivery reports. This setting can be used to determine if all the servers in the organization can send "Out of Office" messages.'
  desc 'check', 'Note: Automated replies to .MIL or .GOV sites are allowed.

Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain | Select Name, Identity, AutoReplyEnabled
If the value of “AutoReplyEnabled” is set to “True” and is configured to only Reply to .MIL or .GOV sites, this is not a finding.

If the value of "AutoReplyEnabled" is not set to "False", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'IdentityName'> -AutoReplyEnabled $false

Note: The <IdentityName> value must be in single quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30629r497053_chk'
  tag severity: 'medium'
  tag gid: 'V-228396'
  tag rid: 'SV-228396r612748_rule'
  tag stig_id: 'EX16-MB-000520'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-30614r496985_fix'
  tag 'documentable'
  tag legacy: ['SV-95417', 'V-80707']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
