control 'SV-4116' do
  title 'The system is configured to allow name-release attacks.'
  desc 'Prevents a denial-of-service (DoS) attack against a WINS server. The DoS consists of sending a NetBIOS Name Release Request to the server for each entry in the servers cache, causing a response delay in the normal operation of the servers WINS resolution capability.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “MSS: (NoNameReleaseOnDemand) Allow computer to ignore NetBIOS name release requests except from WINS servers” is not set to “Enabled”, then this is a finding.
 
The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netbt\\Parameters\\

Value Name:  NoNameReleaseOnDemand

Value Type:  REG_DWORD
Value:  1
 
Note: The NetBIOS name for the system will no longer appear under ‘My Network Places’.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (NoNameReleaseOnDemand) Allow computer to ignore NetBIOS name release requests except from WINS servers” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-311r1_chk'
  tag severity: 'low'
  tag gid: 'V-4116'
  tag rid: 'SV-4116r1_rule'
  tag gtitle: 'Name-Release Attacks'
  tag fix_id: 'F-5723r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
