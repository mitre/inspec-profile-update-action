control 'SV-48061' do
  title 'Users must be warned in advance of their passwords expiring.'
  desc 'Creating strong passwords that can be remembered by users requires some thought.  By giving the user advance warning, the user has time to construct a sufficiently strong password.  This setting configures the system to display a warning to users telling them how many days are left before their password expires.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Interactive Logon: Prompt user to change password before expiration" is not set to  "14" days or more, this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: PasswordExpiryWarning

Value Type: REG_DWORD
Value: 14'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Prompt user to change password before expiration" to "14" days or more.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44800r1_chk'
  tag severity: 'low'
  tag gid: 'V-1172'
  tag rid: 'SV-48061r1_rule'
  tag stig_id: 'WN08-SO-000025'
  tag gtitle: 'Password Expiration Warning'
  tag fix_id: 'F-41199r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
