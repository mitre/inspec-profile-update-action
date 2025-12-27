control 'SV-237940' do
  title 'The IBM z/VM Portmapper server virtual machine userID must be included in the AUTOLOG statement of the TCP/IP server configuration file.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

Bidirectional authentication solutions include, but are not limited to, IEEE 802.1x and Extensible Authentication Protocol [EAP], RADIUS server with EAP-Transport Layer Security [TLS] authentication, Kerberos, and SSL mutual authentication.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area network, wide area network, or the Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply this requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Examine the TCP/IP configuration for "AUTOLOG".

If the userID for auto logger is not in the "AUTOLOG" statement of the TCP/IP server configuration file, this is a finding.'
  desc 'fix', 'Include the Portmapper server virtual machine userID in the "AUTOLOG" statement of the TCP/IP server configuration file.

The Portmapper server is then automatically started when TCP/IP is initialized. The IBM default userID for this server is PORTMAP, but review installation to assure proper ID is included.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41150r859003_chk'
  tag severity: 'medium'
  tag gid: 'V-237940'
  tag rid: 'SV-237940r859005_rule'
  tag stig_id: 'IBMZ-VM-000960'
  tag gtitle: 'SRG-OS-000379-GPOS-00164'
  tag fix_id: 'F-41109r859004_fix'
  tag 'documentable'
  tag legacy: ['SV-93633', 'V-78927']
  tag cci: ['CCI-001997']
  tag nist: ['IA-5 (4)']
end
