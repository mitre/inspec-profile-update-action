control 'SV-44056' do
  title 'SPAM evaluation filter must be enabled.'
  desc "By performing filtering at the perimeter, up to 90% of SPAM, malware, and other undesirable messages may be eliminated from the transport message stream, preventing their entry into the Exchange environment.  This significantly reduces the attack vector for inbound email-borne SPAM and malware.
SPAM evaluation (heuristic) filters scan inbound email messages for evidence of SPAM and other attacks that primarily use 'Social Engineering' techniques.  Upon evaluation completion, a rating is assigned to each message estimating the likelihood of its being SPAM.  Upon arrival at the destination mailbox, the junk mail filter threshold (also configurable) determines whether the message will be withheld from delivery, delivered to the junk mail folder, or delivered to the user’s inbox."
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ContentFilterConfig | Select Name, Identity, Enabled

If the value of 'Enabled' is not set to 'True', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-ContentFilterConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33636'
  tag rid: 'SV-44056r1_rule'
  tag stig_id: 'Exch-2-327'
  tag gtitle: 'Exch-2-327'
  tag fix_id: 'F-37528r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
