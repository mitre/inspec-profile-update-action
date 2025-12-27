control 'SV-48457' do
  title 'Use of Microsoft accounts to log on must be blocked.'
  desc 'Control of logon credentials and the system must be maintained within the enterprise.  Linking an account to an outside vendor could provide an opening if the account is compromised.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options. 

If the value for "Accounts: Block Microsoft accounts" is not set to "Users can't add or log on with Microsoft accounts", this is a finding.)
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Block Microsoft accounts" to "Users can't add or log on with Microsoft accounts".)
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45120r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36771'
  tag rid: 'SV-48457r2_rule'
  tag stig_id: 'WN08-SO-000002'
  tag gtitle: 'WN08-SO-000002'
  tag fix_id: 'F-41584r2_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
