control 'SV-234378' do
  title 'When using PKI-based authentication for user access, the UEM server must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted. To meet this requirement, the information system must create trusted channels between itself and remote trusted authorized IT product (e.g., syslog server) entities that protect the confidentiality and integrity of communications. The information system must create trusted paths between itself and remote administrators and users that protect the confidentiality and integrity of communications.

A trust anchor is an authoritative entity represented via a public key and associated data. It is most often used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. However, applications that do not use a trusted path are not approved for non-local and remote management of DoD information systems.

Use of SSHv2 to establish a trusted channel is approved. Use of FTP, TELNET, HTTP, and SNMPV1 is not approved since they violate the trusted channel rule set. Use of web management tools that are not validated by common criteria my also violate trusted channel rule set.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement. 

Satisfies:FIA_X509_EXT.1.1(1), FIA_X509_EXT.2.1, FIA_X509_EXT.2.2'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

When using PKI-based authentication for user access, verify the UEM server validates certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

If the UEM server uses PKI-based authentication for user access but does not validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor, this is a finding.'
  desc 'fix', 'When using PKI-based authentication for user access, configure the UEM server to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37563r614144_chk'
  tag severity: 'medium'
  tag gid: 'V-234378'
  tag rid: 'SV-234378r879612_rule'
  tag stig_id: 'SRG-APP-000175-UEM-000105'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-37528r614145_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
