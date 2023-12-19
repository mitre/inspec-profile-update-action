control 'SV-242234' do
  title 'The TippingPoint SMS must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Verify the SMS client requires locking of account after three invalid login attempts. 

Navigate to Edit >> Preferences.

If the checkbox for "Lock user after failed login attempts" is not checked, or if the threshold is not set to 3, this is a finding.'
  desc 'fix', 'In the Trend Micro TippingPoint system, ensure the SMS client is requiring locking of account after three invalid login attempts: 

1. Navigate to Edit >> Preferences.
2. Click the checkbox for "Lock user after failed login attempts".
3. Under threshold enter 3.
4. Click OK to save.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45509r710707_chk'
  tag severity: 'medium'
  tag gid: 'V-242234'
  tag rid: 'SV-242234r710709_rule'
  tag stig_id: 'TIPP-NM-000040'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-45467r710708_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
