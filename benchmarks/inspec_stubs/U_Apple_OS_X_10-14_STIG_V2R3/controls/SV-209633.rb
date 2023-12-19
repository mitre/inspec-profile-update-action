control 'SV-209633' do
  title 'The macOS system must authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

Bidirectional authentication solutions include, but are not limited to, IEEE 802.1x and Extensible Authentication Protocol [EAP], RADIUS server with EAP-Transport Layer Security [TLS] authentication, Kerberos, and SSL mutual authentication.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area network, wide area network, or the Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply this requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'For systems where Wi-Fi is not approved for use, run the following command to disable the Wi-Fi service:

To list the network devices that are enabled on the system, run the following command:

/usr/bin/sudo /usr/sbin/networksetup -listallnetworkservices

If the Wi-Fi service name is not preceded by an asterisk(*), this is a finding.'
  desc 'fix', 'To disable a network device, run the following command:

/usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled Wi-Fi off'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9884r282381_chk'
  tag severity: 'medium'
  tag gid: 'V-209633'
  tag rid: 'SV-209633r610285_rule'
  tag stig_id: 'AOSX-14-004020'
  tag gtitle: 'SRG-OS-000379-GPOS-00164'
  tag fix_id: 'F-9884r282382_fix'
  tag 'documentable'
  tag legacy: ['SV-104731', 'V-95585']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
