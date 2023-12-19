control 'SV-235727' do
  title 'Data Synchronization must be disabled.'
  desc 'Disables data synchronization in Microsoft Edge. This policy also prevents the sync consent prompt from appearing.

If this policy is not set or applied as recommended, users will be able to turn sync on or off. If this policy is applied as mandatory, users will not be able to turn on sync.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Disable synchronization of data using Microsoft sync services" must be set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "SyncDisabled" is not set to "REG_DWORD = 1", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Disable synchronization of data using Microsoft sync services" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38946r766841_chk'
  tag severity: 'low'
  tag gid: 'V-235727'
  tag rid: 'SV-235727r766843_rule'
  tag stig_id: 'EDGE-00-000010'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38909r766842_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
