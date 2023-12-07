control 'SV-48043' do
  title 'Unencrypted passwords must not be sent to third-party SMB Servers.'
  desc 'Some non-Microsoft SMB servers only support unencrypted (plain text) password authentication.  Sending plain text passwords across the network, when authenticating to an SMB server, reduces the overall security of the environment.  Check with the vendor of the SMB server to see if there is a way to support encrypted password authentication.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Microsoft Network Client: Send unencrypted password to third-party SMB servers" is not set to "Disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

Value Name:  EnablePlainTextPassword

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft Network Client: Send unencrypted password to third-party SMB servers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-62017r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1141'
  tag rid: 'SV-48043r2_rule'
  tag stig_id: 'WN08-SO-000030'
  tag gtitle: 'Unencrypted Password is Sent to SMB Server.'
  tag fix_id: 'F-66913r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
