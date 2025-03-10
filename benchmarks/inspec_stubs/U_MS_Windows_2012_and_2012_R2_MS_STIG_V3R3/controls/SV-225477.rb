control 'SV-225477' do
  title 'The service principal name (SPN) target name validation level must be turned off.'
  desc "If a service principle name (SPN) is provided by the client, it is validated against the server's list of SPNs.  Implementation may disrupt file and print sharing capabilities."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\

Value Name: SmbServerNameHardeningLevel

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Server SPN target name validation level" to "Off".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27176r471773_chk'
  tag severity: 'medium'
  tag gid: 'V-225477'
  tag rid: 'SV-225477r569185_rule'
  tag stig_id: 'WN12-SO-000035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27164r471774_fix'
  tag 'documentable'
  tag legacy: ['SV-53175', 'V-21950']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
