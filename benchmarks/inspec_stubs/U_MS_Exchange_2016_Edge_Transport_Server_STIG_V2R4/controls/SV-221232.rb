control 'SV-221232' do
  title 'Exchange messages with a blank sender field must be rejected.'
  desc 'By performing filtering at the perimeter, up to 90 percent of spam, malware, and other undesirable messages are eliminated from the message stream rather than admitting them into the mail server environment. Anonymous email (messages with blank sender fields) cannot be replied to. Messages formatted in this way may be attempting to hide their true origin to avoid responses or to spam any receiver with impunity while hiding their source of origination.

Rather than spend resources and risk infection while evaluating them, it is recommended that these messages be filtered immediately upon receipt and not forwarded to end users.'
  desc 'check', 'This requirement is N/A for SIPR enclaves.  

This requirement is N/A if the organization subscribes to EEMSG or other similar DoD enterprise protections for email services.

Open the Exchange Management Shell and enter the following command:

Get-SenderFilterConfig | Select Name, Action 

If the value of "Action" is not set to "Reject", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderFilterConfig -Action Reject'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22947r411822_chk'
  tag severity: 'medium'
  tag gid: 'V-221232'
  tag rid: 'SV-221232r612603_rule'
  tag stig_id: 'EX16-ED-000330'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22936r411823_fix'
  tag 'documentable'
  tag legacy: ['SV-95255', 'V-80545']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
