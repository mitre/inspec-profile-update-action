control 'SV-32441' do
  title 'The service principal name (SPN) target name validation level will be turned off.'
  desc 'If a service principle name (SPN) is provided by the client, it is validated against the server’s list of SPNs.  This setting can cause disruptions in file and printer services.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options.

If the value for “Microsoft network server: Server SPN target name validation level” is not set to “Off”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\

Value Name:  SmbServerNameHardeningLevel

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Microsoft Network Server: Server SPN target name validation level” to “Off”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32782r1_chk'
  tag severity: 'medium'
  tag gid: 'V-21950'
  tag rid: 'SV-32441r1_rule'
  tag gtitle: 'SPN Target Name Validation Level'
  tag fix_id: 'F-28855r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
