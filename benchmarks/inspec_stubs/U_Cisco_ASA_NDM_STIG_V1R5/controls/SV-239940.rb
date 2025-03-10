control 'SV-239940' do
  title 'The Cisco ASA must be configured to use at least two authentication servers to authenticate users prior to granting administrative access.'
  desc "Centralized management of authentication settings increases the security of remote and non-local access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the Cisco ASA configuration to verify the device is configured to use at least two authentication servers as primary source for authentication.

Step 1: Verify that an AAA group is configured for login authentication for both in-band and console access methods.

aaa authentication serial console RADIUS_GROUP LOCAL
aaa authentication ssh console RADIUS_GROUP LOCAL

Step 2: Verify that an AAA group and server has been defined for the group referenced in the above example.

aaa-server RADIUS_GROUP protocol radius
aaa-server RADIUS_GROUP (NDM_INTERFACE) host 10.1.48.10
 key *****
aaa-server RADIUS_GROUP (NDM_INTERFACE) host 10.1.48.11
 key *****

If the Cisco ASA is not configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to use at least two authentication servers as shown in the following example.

Step 1: Define the authentication group and protocol.

ASA(config)# aaa-server RADIUS_GROUP protocol radius

Step 2: Define the authentication servers. 

ASA(config)# aaa-server RADIUS_GROUP (NDM_INTERFACE) host 10.1.48.10         
ASA(config-aaa-server-host)# key bobby
ASA(config-aaa-server-host)# exit
ASA(config)# aaa-server RADIUS_GROUP (NDM_INTERFACE) host 10.1.48.11         
ASA(config-aaa-server-host)# key bobby2
ASA(config-aaa-server-host)# exit

Step 3: Use the AAA server for login authentication for both in-band and console access methods.

ASA(config)# aaa authentication serial console RADIUS_GROUP LOCAL
ASA(config)# aaa authentication ssh console RADIUS_GROUP LOCAL
ASA(config)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43173r916028_chk'
  tag severity: 'high'
  tag gid: 'V-239940'
  tag rid: 'SV-239940r916111_rule'
  tag stig_id: 'CASA-ND-001310'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-43132r916029_fix'
  tag 'documentable'
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
