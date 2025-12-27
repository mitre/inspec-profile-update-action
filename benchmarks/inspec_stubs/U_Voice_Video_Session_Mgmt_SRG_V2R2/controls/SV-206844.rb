control 'SV-206844' do
  title 'The Voice Video Session Manager must require Voice Video endpoints to re-register at least every three (3) hours.'
  desc 'Device registration is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system. Registration is the process of authorizing endpoints to communicate with the session manager. Registration occurs with the SIP server in VoIP systems and with a gatekeeper in H.323 systems. Without enforcing registration, an adversary could impersonate a legitimate device on the Voice Video network.'
  desc 'check', 'Verify the Voice Video Session Manager requires Voice Video endpoints to re-register at least every three hours.

If the Voice Video Session Manager does not require Voice Video endpoints to re-register or does not enforce re-registration at least every three hours, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to re-register Voice Video endpoints at least every three hours.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7099r364721_chk'
  tag severity: 'medium'
  tag gid: 'V-206844'
  tag rid: 'SV-206844r508661_rule'
  tag stig_id: 'SRG-NET-000338-VVSM-00006'
  tag gtitle: 'SRG-NET-000338'
  tag fix_id: 'F-7099r364722_fix'
  tag 'documentable'
  tag legacy: ['V-62123', 'SV-76613']
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
