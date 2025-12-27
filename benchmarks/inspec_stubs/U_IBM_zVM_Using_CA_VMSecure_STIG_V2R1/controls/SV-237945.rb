control 'SV-237945' do
  title 'The IBM z/VM TCP/IP SECUREDATA option for FTP must be set to REQUIRED.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to support transmission protection mechanisms such as TLS, SSL VPNs, or IPsec.

The SECUREDATA statement specifies the FTP server-wide minimum security level for data connections.

'
  desc 'check', 'Examine the FTP Server configuration file.

If there is no “SECUREDATA” statement, this is a finding.

If the “SECUREDATA” statement specifies “REQUIRED”, this is not a finding.

Note: If there is no "SECUREDATA" or the "SECUREDATA" specifies "ALLOWED" but there is a documented implementation plan with a definite completion date for setting "SECUREDATA" to "REQUIRED" on file with the ISSM, this can be downgraded to a CAT III.'
  desc 'fix', 'Configure the “SECUREDATA” statement in the FTP server configuration file to specify “REQUIRED”.

Note: Care should be taken before implementing this requirement in a production environment. Develop a documented plan of action that has a definite completion date. File the plan with the ISSM.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41155r649673_chk'
  tag severity: 'medium'
  tag gid: 'V-237945'
  tag rid: 'SV-237945r649675_rule'
  tag stig_id: 'IBMZ-VM-001040'
  tag gtitle: 'SRG-OS-000425-GPOS-00189'
  tag fix_id: 'F-41114r649674_fix'
  tag satisfies: ['SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag legacy: ['SV-93643', 'V-78937']
  tag cci: ['CCI-002420', 'CCI-002422']
  tag nist: ['SC-8 (2)', 'SC-8 (2)']
end
