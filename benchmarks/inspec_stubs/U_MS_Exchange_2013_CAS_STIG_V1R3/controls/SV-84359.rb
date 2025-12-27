control 'SV-84359' do
  title 'Exchange must have Send Fatal Errors to Microsoft disabled.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. This setting enables an automated log entry to be sent to Microsoft giving general details about the nature and location of the error. Microsoft, in turn, uses this information to improve the robustness of their product.

While this type of debugging information would not ordinarily contain sensitive information, it may alert eavesdroppers to the existence of problems in your Exchange organization. At the very least, it could alert them to (possibly) advantageous timing to mount an attack. At worst, it may provide them with information as to which aspects of Exchange are causing problems and might be vulnerable (or at least sensitive) to attack.

All system errors in Exchange will result in outbound traffic that may be identified by an eavesdropper. For this reason, the "Report Fatal Errors to Microsoft" feature must be disabled.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExchangeServer –status | Select Name, Identity, ErrorReportingEnabled

For each Identity, if the value of ErrorReportingEnabled is not set to False, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-ExchangeServer -Identity <IdentityName> -ErrorReportingEnabled $false

Note: The <IdentityName> value must be in quotes.

Repeat the procedure for each Identity.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70181r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69737'
  tag rid: 'SV-84359r1_rule'
  tag stig_id: 'EX13-CA-000060'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-75943r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
