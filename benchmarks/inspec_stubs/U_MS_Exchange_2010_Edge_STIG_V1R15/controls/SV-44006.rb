control 'SV-44006' do
  title 'Send Connectors delivery retries must be controlled.'
  desc 'This setting controls the rate at which delivery attempts from the home domain are retried, user notifications are issued, and notes the expiration time when the message will be discarded.  

If delivery retry attempts are too frequent, servers will generate network congestion. If too far apart, then messages may remain queued longer than necessary, potentially raising disk resource requirements.    

The default values of these fields should be adequate for most environments.  Administrators may wish to modify the values as a result, but changes should be documented in the System Security Plan.

NOTE: Transport configuration settings apply to the organization/global level of the Exchange SMTP path.  By checking and setting them at the Hub server the setting will apply to both Hub and Edge roles.'
  desc 'check', "Obtain the Email Domain Security Plan (EDSP) and locate the value for 'Transient Failure Retry Count'.

Open the Exchange Management Shell and enter the following command:

Get-TransportServer -Identity <'ServerUnderReview'> | Select Name, Identity, TransientFailureRetryCount

If the value of 'TransientFailureRetryCount' is set to 10 or less, this is not a finding.

If the value of 'TransientFailureRetryCount' is set to more than 10, and has signoff and risk acceptance in the EDSP, this is not a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-TransportServer -Identity <'ServerUnderReview'> -TransientFailureRetryCount 10 or other value as identified by the EDSP."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41691r1_chk'
  tag severity: 'low'
  tag gid: 'V-33586'
  tag rid: 'SV-44006r1_rule'
  tag stig_id: 'Exch-2-754'
  tag gtitle: 'Exch-2-754'
  tag fix_id: 'F-37476r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
