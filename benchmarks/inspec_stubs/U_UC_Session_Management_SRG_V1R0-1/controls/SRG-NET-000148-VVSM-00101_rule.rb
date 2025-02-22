control 'SRG-NET-000148-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to uniquely identify each Voice Video Endpoint device before registration.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Typically, devices can be identified by MAC or IP address, but certificates provide a greater level of security. Identification of devices works with registration of devices as part of a defense in depth approach to Voice Video networks. Registration is the process of authorizing endpoints to communicate with the session manager. Registration occurs with the SIP server in VoIP systems and with a gatekeeper in H.323 systems. Without enforcing registration, an adversary could impersonate a legitimate device on the Voice Video network.'
  desc 'check', 'Verify the Unified Communications Session Manager uniquely identifies all Voice Video Endpoint devices before registration.

If the Unified Communications Session Manager does not uniquely identify all Voice Video Endpoint devices before registration, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to uniquely identify all Voice Video Endpoint devices before registering those devices.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000148-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000148-VVSM-00101'
  tag rid: 'SRG-NET-000148-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000148-VVSM-00101'
  tag gtitle: 'SRG-NET-000148-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000148-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
