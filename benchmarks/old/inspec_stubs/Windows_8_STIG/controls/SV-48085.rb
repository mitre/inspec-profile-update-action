control 'SV-48085' do
  title 'The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.'
  desc 'This setting ensures that the system uses algorithms that are FIPS-compliant for encryption, hashing, and signing.  FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the algorithms used for all OS encryption functions.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\

Value Name: Enabled

Value Type: REG_DWORD
Value: 1
 
Warning: Clients with this setting enabled will not be able to communicate via digitally encrypted or signed protocols with servers that do not support these algorithms.  Both the browser and web server must be configured to use TLS, or the browser will not be able to connect to a secure site.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44824r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3383'
  tag rid: 'SV-48085r1_rule'
  tag stig_id: 'WN08-SO-000074'
  tag gtitle: 'FIPS Compliant Algorithms'
  tag fix_id: 'F-41223r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Clients with this setting enabled will not be able to communicate via digitally encrypted or signed protocols with servers that do not support these algorithms.  Both the browser and web server must be configured to use TLS, or the browser will not be able to connect to a secure site.'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
