control 'SV-86183' do
  title 'The CA API Gateway must obtain LDAPS server certificates securely to use bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication.'
  desc 'check', 'Verify the LDAPS server certificate is in "/etc/openldap/cacerts". Verify TLS_REQCERT is set to demand in "/etc/openldap/ldap.conf".

If the LDAPS server certificate is not in "/etc/openldap/cacerts", this is a finding. 

If "TLS_REQCERT" is not set to demand in "/etc/openldap/ldap.conf", this is a finding.'
  desc 'fix', 'Configure LDAPS/LDAPS+RADIUS to use LDAPS server certificates for bidirectional authentication that is cryptographically based.

Place the LDAPS server certificate in "/etc/openldap/cacerts". 

Set "TLS_REQCERT" to demand in "/etc/openldap/ldap.conf".'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71559'
  tag rid: 'SV-86183r1_rule'
  tag stig_id: 'CAGW-DM-000300'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-77883r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
