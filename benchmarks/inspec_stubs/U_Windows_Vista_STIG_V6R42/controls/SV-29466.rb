control 'SV-29466' do
  title 'Secure Removable Media – CD-ROM'
  desc 'This check verifies that Windows is configured to not limit access to CD drives when a user is logged on locally per the FDCC.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view.

Navigate to Local Policies -> Security Options.
If the value for “Devices: Restrict CD-ROM access to locally logged-on user only” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: AllocateCDRoms

Value Type:  REG_SZ
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Restrict CD-ROM access to locally logged-on user only” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-18082r1_chk'
  tag severity: 'low'
  tag gid: 'V-17373'
  tag rid: 'SV-29466r1_rule'
  tag gtitle: 'Secure Removable Media – CD-ROM'
  tag fix_id: 'F-27980r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
