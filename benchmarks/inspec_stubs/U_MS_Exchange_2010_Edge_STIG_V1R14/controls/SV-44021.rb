control 'SV-44021' do
  title 'External/Internet bound automated response messages must be disabled.'
  desc "SPAM originators, in an effort to refine mailing lists, sometimes use a technique where they monitor transmissions for automated bounce back messages, such as 'Out of Office' messages.  Automated messages include such items as Out of Office responses, non-delivery messages, or automated message forwarding.

Automated bounce back messages can be used by a third party to determine if users exist on the server. This can result in the disclosure of active user accounts to third parties, paving the way for possible future attacks."
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain -Identity 'default' | Select Name, Identity, AllowedOOFType

If the value of 'AllowedOOFType' is set to 'External' or 'ExternalLegacy', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -AllowedOOFType 'InternalLegacy' -Identity 'default'"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41708r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33601'
  tag rid: 'SV-44021r1_rule'
  tag stig_id: 'Exch-2-811'
  tag gtitle: 'Exch-2-811'
  tag fix_id: 'F-37493r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
