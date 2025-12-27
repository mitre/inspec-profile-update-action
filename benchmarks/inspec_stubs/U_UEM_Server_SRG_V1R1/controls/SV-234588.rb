control 'SV-234588' do
  title 'The UEM server must connect to [assignment: [list of applications]] and managed mobile devices with an authenticated and secure (encrypted) connection to protect the confidentiality and integrity of transmitted information.'
  desc 'Applications may include the following: update server, database, and enterprise directory service. Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPSEC.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

This requirement applies to any application to which the server connects (for example SQL server, Active Directory). 

Satisfies:FMT_SMF.1.1(2) b, FTP_ITC.1.1(1), FTP_ITC.1.2(1), FTP_ITC.1.3(1)  
Reference:PP-MDM-431009'
  desc 'check', 'Verify the UEM server connects to applications and managed mobile devices with an authenticated and secure (encrypted) connection to protect the confidentiality and integrity of transmitted information.

If the UEM server does not connect to applications and managed mobile devices with an authenticated and secure (encrypted) connection to protect the confidentiality and integrity of transmitted information, this is a finding.'
  desc 'fix', 'Configure the UEM server to connect to applications and managed mobile devices with an authenticated and secure (encrypted) connection to protect the confidentiality and integrity of transmitted information.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37773r615997_chk'
  tag severity: 'high'
  tag gid: 'V-234588'
  tag rid: 'SV-234588r617355_rule'
  tag stig_id: 'SRG-APP-000439-UEM-000313'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-37738r615399_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
