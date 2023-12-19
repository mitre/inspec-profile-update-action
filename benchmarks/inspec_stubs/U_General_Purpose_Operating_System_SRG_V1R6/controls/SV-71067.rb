control 'SV-71067' do
  title 'The operating system must authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

Bidirectional authentication solutions include, but are not limited to, IEEE 802.1x and Extensible Authentication Protocol [EAP], RADIUS server with EAP-Transport Layer Security [TLS] authentication, Kerberos, and SSL mutual authentication.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area network, wide area network, or the Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply this requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Verify the operating system authenticates all endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57377r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56807'
  tag rid: 'SV-71067r1_rule'
  tag stig_id: 'SRG-OS-000379-GPOS-00164'
  tag gtitle: 'SRG-OS-000379-GPOS-00164'
  tag fix_id: 'F-61703r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
