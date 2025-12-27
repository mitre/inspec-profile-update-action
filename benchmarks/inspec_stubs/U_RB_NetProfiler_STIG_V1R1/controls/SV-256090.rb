control 'SV-256090' do
  title 'The Riverbed NetProfiler must be configured to implement cryptographic mechanisms using a FIPS 140-2/140-3 validated algorithm to protect the confidentiality and integrity of all cryptographic functions.'
  desc 'If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and allowing hijacking of maintenance sessions.

Network devices using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2/140-3 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DOD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.

Currently, HMAC is the only FIPS-validated algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2/140-3 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

All protocols (e.g., SNMPv3, SSHv2, NTP, HTTPS, HMAC, password authentication, remote communications, password encryption, random number/session ID generation, and other protocols and cryptograph applications/functions that require server/client authentication) are to be FIPS 140-2/140-3 validated. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.

'
  desc 'check', 'Go to Administration >> Appliance Security >> Security Compliance. 

Check under "Operational Modes". 

If "FIPS 140-2 Compatible Cryptography" is not enabled, this is a finding.'
  desc 'fix', 'Go to Administration >> Appliance Security >> Security Compliance. 

Under "Operational Modes", enable "FIPS 140-2 Compatible Cryptography".

NOTE: Configuring FIPS mode is the required DOD configuration. However, the severity of this requirement can be decreased to a CAT III if the alternative manual configuration is used to configure individual protocols because this allows non-FIPS validated algorithms to be used for some functions.'
  impact 0.7
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59764r882776_chk'
  tag severity: 'high'
  tag gid: 'V-256090'
  tag rid: 'SV-256090r882778_rule'
  tag stig_id: 'RINP-DM-000054'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-59707r882777_fix'
  tag satisfies: ['SRG-APP-000412-NDM-000331', 'SRG-APP-000156-NDM-000250', 'SRG-APP-000171-NDM-000258', 'SRG-APP-000172-NDM-000259', 'SRG-APP-000179-NDM-000265', 'SRG-APP-000224-NDM-000270', 'SRG-APP-000411-NDM-000330']
  tag 'documentable'
  tag cci: ['CCI-000196', 'CCI-000197', 'CCI-000803', 'CCI-001188', 'CCI-001941', 'CCI-002890', 'CCI-003123']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (c)', 'IA-7', 'SC-23 (3)', 'IA-2 (8)', 'MA-4 (6)', 'MA-4 (6)']
end
