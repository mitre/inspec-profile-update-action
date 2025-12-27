control 'SV-258590' do
  title 'The ICS, when utilizing PKI-based authentication, must be configured to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted. To meet this requirement, the information system must create trusted channels between itself and remote trusted authorized IT product (e.g., syslog server) entities that protect the confidentiality and integrity of communications. The information system must create trusted paths between itself and remote administrators and users that protect the confidentiality and integrity of communications.

A trust anchor is an authoritative entity represented via a public key and associated data. It is most often used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. However, applications that do not use a trusted path are not approved for nonlocal and remote management of DOD information systems.

Use of SSHv2 to establish a trusted channel is approved. Use of FTP, TELNET, HTTP, and SNMPV1 is not approved since they violate the trusted channel rule set. Use of web management tools that are not validated by common criteria may also violate the trusted channel rule set.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.

'
  desc 'check', 'In the ICS Web UI, navigate to System >> Configuration >> Certificates >> Trusted Client CAs.
1. Click the first DOD client CA.
2. Verify the item "Use OCSP with CRL fallback" is selected under the "Client certificate status checking" setting.
3. Check each client certificate CA. Verify the setting "Use OCSP with CRL fallback" is selected.

For PKI-based authentication, if the ICS does not validate certificates by constructing a certification path (which includes revocation status information) to an accepted trust anchor, this is a finding.'
  desc 'fix', 'Configure status checking on the ICS. The focus for this requirement is on the path, so the installation of the device certificates is not included.

In the ICS Web UI, navigate to System >> Configuration >> Certificates >> Trusted Client CAs.
1. Click the first DOD client CA.
2. Enable "Use OCSP with CRL fallback" under "Client certificate status checking".
3. Repeat these steps for every remaining client certificate CA.'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62330r930456_chk'
  tag severity: 'medium'
  tag gid: 'V-258590'
  tag rid: 'SV-258590r930458_rule'
  tag stig_id: 'IVCS-VN-000210'
  tag gtitle: 'SRG-NET-000164-VPN-000560'
  tag fix_id: 'F-62239r930457_fix'
  tag satisfies: ['SRG-NET-000164-VPN-000560', 'SRG-NET-000512-VPN-002230', 'SRG-NET-000580-VPN-002410']
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-000366']
  tag nist: ['IA-5 (2) (b) (1)', 'CM-6 b']
end
