control 'SV-226283' do
  title 'The maximum age for machine account passwords must be set to requirements.'
  desc 'Computer account passwords are changed automatically on a regular basis.  This setting controls the maximum password age that a machine account may have.  This setting must be set to no more than 30 days, ensuring the machine changes its password monthly.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: MaximumPasswordAge

Value Type: REG_DWORD
Value: 30 (or less, but not 0)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Maximum machine account password age" to "30" or less (excluding "0" which is unacceptable).'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27985r476693_chk'
  tag severity: 'low'
  tag gid: 'V-226283'
  tag rid: 'SV-226283r569184_rule'
  tag stig_id: 'WN12-SO-000016'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27973r476694_fix'
  tag 'documentable'
  tag legacy: ['SV-52887', 'V-3373']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
