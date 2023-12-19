control 'SV-207306' do
  title 'Exchange Send connectors delivery retries must be controlled.'
  desc 'This setting controls the rate at which delivery attempts from the home domain are retried and user notifications are issued and notes the expiration time when the message will be discarded.  

If delivery retry attempts are too frequent, servers will generate network congestion. If too far apart, messages may remain queued longer than necessary, potentially raising disk resource requirements.

The default values of these fields should be adequate for most environments. Administrators may wish to modify the values as a result, but changes should be documented in the System Security Plan.

Note: Transport configuration settings apply to the organization/global level of the Exchange SMTP path. By checking and setting them at the Hub server the setting will apply to both Hub and Edge roles.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the value for Transient Failure Retry Count.

Open the Exchange Management Shell and enter the following command:

Get-TransportService  | Select Name, Identity, TransientFailureRetryCount

If the value of TransientFailureRetryCount is not set to 10 or less, this is a finding.

or

If the value of TransientFailureRetryCount is set to more than 10 or has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Set-TransportService -Identity <'IdentityName'> -TransientFailureRetryCount 10 

Note: The <ServerIdentity> value must be in quotes.

or

The value as identified by the EDSP that has obtained a signoff with risk acceptance."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7564r393431_chk'
  tag severity: 'low'
  tag gid: 'V-207306'
  tag rid: 'SV-207306r615936_rule'
  tag stig_id: 'EX13-MB-000200'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-7564r393432_fix'
  tag 'documentable'
  tag legacy: ['SV-84641', 'V-70019']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
