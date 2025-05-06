control 'SV-44036' do
  title 'Exchange must not send Customer Experience reports to Microsoft.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve availability. This setting enables an automated entry to be sent to Microsoft giving general details about how the product is used.  Microsoft, in turn, uses this information to improve the robustness of their product.

While this type of information does not ordinarily contain sensitive information, it may alert eavesdroppers to the existence of the environment and its configurations.  It could alert them to (possibly) advantageous timing or weaknesses toward which to mount an attack.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-OrganizationConfig
If the value for CustomerFeedbackEnabled is not set to 'False', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-OrganizationConfig -CustomerFeedbackEnabled $false'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41723r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33616'
  tag rid: 'SV-44036r1_rule'
  tag stig_id: 'Exch-2-831'
  tag gtitle: 'Exch-2-831'
  tag fix_id: 'F-37508r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
