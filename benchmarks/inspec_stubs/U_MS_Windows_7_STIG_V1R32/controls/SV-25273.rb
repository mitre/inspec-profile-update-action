control 'SV-25273' do
  title 'The service principal name (SPN) target name validation level must be configured to Accept if provided by client.'
  desc "If a service principle name (SPN) is provided by the client, it is validated against the server's list of SPNs, aiding in the prevention of spoofing."
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Microsoft network server: Server SPN target name validation level" is not set to "Accept if provided by client", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\

Value Name:  SmbServerNameHardeningLevel

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft network server: Server SPN target name validation level" to "Accept if provided by client".'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60807r2_chk'
  tag severity: 'medium'
  tag gid: 'V-21950'
  tag rid: 'SV-25273r2_rule'
  tag gtitle: 'SPN Target Name Validation Level'
  tag fix_id: 'F-65539r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
