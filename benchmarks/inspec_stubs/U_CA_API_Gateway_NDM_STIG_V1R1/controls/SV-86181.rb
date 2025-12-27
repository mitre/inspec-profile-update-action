control 'SV-86181' do
  title 'The CA API Gateway must authenticate LDAPS endpoint devices before establishing a network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication.'
  desc 'check', 'Using the "ssgconfig" menu subsystem, confirm LDAP (Secure) has been configured via 1) Configure system settings >> 4) Configure authentication method item 2 or 4. 

Confirm the answer to the question "Do you want to specify the URL to a PEM containing the certificate (y/n) [y]:" is "y". 

Ensure the answer to question "Specify the URL where the PEM formatted CA certificate can be located [ldaps://smldap.l7tech.com:636]:" is a trusted source of the certificate.

If the LDAP is not correctly configured, this is a finding.'
  desc 'fix', 'Using the "ssgconfig" menu subsystem, set LDAP (Secure) by 1) Configure system settings >> 4) Configure authentication method item 2 or 4. 

Set the answer to the question "Do you want to specify the URL to a PEM containing the certificate (y/n) [y]:" to "y". 

Set the answer to the question "Specify the URL where the PEM formatted CA certificate can be located [ldaps://smldap.l7tech.com:636]:" to a trusted source of the certificate.'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71931r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71557'
  tag rid: 'SV-86181r1_rule'
  tag stig_id: 'CAGW-DM-000290'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-77879r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
