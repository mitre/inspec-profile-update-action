control 'SV-108143' do
  title 'The BlackBerry EMM server must connect to [application: SQL Server] with an authenticated and secure (encrypted) connection to protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPsec.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

SFR ID: FMT_SMF.1.1(2) b / SC-8, SC-8 (1), SC-8 (2)

'
  desc 'check', 'Talk to the site UEM Administrator to confirm the SQL server has been configured to connect to UEM using the TLS connection or confirm during a review of the SQL server.

If the SQL server has not been configured to connect to UEM using the TLS connection, this is a finding.'
  desc 'fix', 'Confirm the Administrator has configured the SQL server to connect to UEM using the TLS connection.'
  impact 0.5
  ref 'DPMS Target BlackBerry Unified Endpoint Manager (UEM) 12.11'
  tag check_id: 'C-97879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99039'
  tag rid: 'SV-108143r1_rule'
  tag stig_id: 'BUEM-12-112060'
  tag gtitle: 'PP-MDM-331009'
  tag fix_id: 'F-104715r1_fix'
  tag satisfies: ['SRG-APP-000439', 'SRG-APP-000440']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']
end
