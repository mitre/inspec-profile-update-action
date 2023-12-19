control 'SV-89403' do
  title 'The MQ Appliance messaging server must implement cryptography mechanisms to protect the integrity of the remote access session.'
  desc 'Encryption is critical for protection of remote access sessions. If encryption is not being used for integrity, malicious users may gain the ability to modify the messaging server configuration. The use of cryptography for ensuring integrity of remote access sessions mitigates that risk.

Messaging servers utilize a web management interface and scripted commands when allowing remote access. Web access requires the use of TLS and scripted access requires using ssh or some other form of approved cryptography. Messaging servers must have a capability to enable a secure remote admin capability.

FIPS 140-2 approved TLS versions include TLS V1.0 or greater.

FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 specifies the preferred configurations for government systems.

'
  desc 'check', "Obtain queue security policy requirements from system admin.

To verify the Advanced Message Security (AMS) policy for a specific queue manager's queues, enter: 
mqcli

To list the policies for each queue, enter:
runmqsc [QMgrName]

To display all policies, enter:
DIS POLICY(*)  

If no security policies are found or the specifics of the security policy does not meet documented queue security requirements, this is a finding."
  desc 'fix', "Advanced Message Security can sign and encrypt messages at the point of production, and then decrypt and authenticate them at the point of consumption. At all points in between, the message is protected, either for integrity (using hashing) or for privacy (using encryption).  Steps for setting up AMS are not included here.  Reference vendor documentation for guidance on setting up AMS.
 
To access the MQ Appliance CLI, enter:
mqcli

runmqsc [QMgrName]

SET POLICY([queue name]) SIGNALG([SHA256, SHA384, or SHA512]) +
ENCALG([3DES, AES128, or AES256]) +
RECIP(['distinguished name (DN) of the message recipient']) +
SIGNER(['Signature DN validated during message retrieval'])
end"
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74585r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74729'
  tag rid: 'SV-89403r1_rule'
  tag stig_id: 'MQMH-AS-000020'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag fix_id: 'F-81343r1_fix'
  tag satisfies: ['SRG-APP-000015-AS-000010', 'SRG-APP-000126-AS-000085', 'SRG-APP-000231-AS-000133', 'SRG-APP-000231-AS-000156', 'SRG-APP-000428-AS-000265', 'SRG-APP-000429-AS-000157', 'SRG-APP-000441-AS-000258', 'SRG-APP-000442-AS-000259']
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-001350', 'CCI-001453', 'CCI-002420', 'CCI-002422', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'AU-9 (3)', 'AC-17 (2)', 'SC-8 (2)', 'SC-8 (2)', 'SC-28 (1)', 'SC-28 (1)']
end
