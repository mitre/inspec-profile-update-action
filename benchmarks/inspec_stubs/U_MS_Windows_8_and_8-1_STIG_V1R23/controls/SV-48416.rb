control 'SV-48416' do
  title 'The service principal name (SPN) target name validation level must be configured to Accept if provided by client.'
  desc "If a service principle name (SPN) is provided by the client, it is validated against the server's list of SPNs, aiding in the prevention of spoofing."
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Microsoft network server: Server SPN target name validation level" is not set to "Accept if provided by client", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\

Value Name: SmbServerNameHardeningLevel

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Server SPN target name validation level" to "Accept if provided by client".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45085r2_chk'
  tag severity: 'medium'
  tag gid: 'V-21950'
  tag rid: 'SV-48416r2_rule'
  tag stig_id: 'WN08-SO-000035'
  tag gtitle: 'SPN Target Name Validation Level'
  tag fix_id: 'F-41547r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
