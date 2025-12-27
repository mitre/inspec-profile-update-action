control 'SV-206829' do
  title 'The Voice Video Session Manager must uniquely identify each Voice Video endpoint device before registration.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Typically, devices can be identified by MAC or IP address but certificates provide a greater level of security. Identification of devices works with registration of devices as part of a defense in depth approach to Voice Video networks. Registration is the process of authorizing endpoints to communicate with the session manager. Registration occurs with the SIP server in VoIP systems and with a gatekeeper in H.323 systems. Without enforcing registration, an adversary could impersonate a legitimate device on the Voice Video network.'
  desc 'check', 'Verify the Voice Video Session Manager uniquely identifies all Voice Video endpoint devices before registration.

If the Voice Video Session Manager does not uniquely identify all Voice Video endpoint devices before registration, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to uniquely identify all Voice Video endpoint devices before registering those devices.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7084r364676_chk'
  tag severity: 'medium'
  tag gid: 'V-206829'
  tag rid: 'SV-206829r508661_rule'
  tag stig_id: 'SRG-NET-000148-VVSM-00004'
  tag gtitle: 'SRG-NET-000148'
  tag fix_id: 'F-7084r364677_fix'
  tag 'documentable'
  tag legacy: ['V-62093', 'SV-76583']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
