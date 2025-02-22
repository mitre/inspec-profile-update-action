control 'SV-75283' do
  title 'The Arista Multilayer Switch must re-authenticate all endpoint devices every 60 minutes or less.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity on the network. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk (e.g., remote connections).

Bidirectional authentication solutions include, but are not limited to, IEEE 802.1x and Extensible Authentication Protocol (EAP) and Radius server with EAP-Transport Layer Security (TLS) authentication.
 
A network connection is any connection with a device that communicates through a network (e.g., local area network, wide area network, or the Internet).

Authentication must use a form of cryptography to ensure a high level of trust and authenticity. Re-authentication must occur to ensure session security.'
  desc 'check', 'This requirement only applies to devices required to employ 802.1X authentication.

Verify that the network device uniquely identifies network-connected endpoint devices and re-authenticates devices every 60 minutes or less. This can be viewed via the "show dot1x all" command. Under the interface configuration for the .1X connected port, the following statements must be present:

ReauthPeriod : 3600 seconds

If the device does not require re-authentication, or if the re-authentication period is longer than 60 minutes, this is a finding.'
  desc 'fix', 'Configure 802.1X on the switch, including the following mandatory parameters in the interface configuration mode:

config
interface Ethernet[X]
 dot1x reauthentication
 dot1x timeout reauth-period 3600'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series L2S'
  tag check_id: 'C-61773r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60827'
  tag rid: 'SV-75283r1_rule'
  tag stig_id: 'AMLS-L2-000140'
  tag gtitle: 'SRG-NET-000151'
  tag fix_id: 'F-66537r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
