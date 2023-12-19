control 'SV-206773' do
  title 'The Voice Video Endpoint used for videoconferencing must electronically verify the Common Access Card (CAC) or derived credentials.'
  desc 'The use of CAC or derived credentials facilitates standardization and reduces the risk of unauthorized access. DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'If the Voice Video Endpoint is a hardware endpoint, this check procedure is Not Applicable.

Verify the Voice Video Endpoint used for videoconferencing electronically verifies the CAC or derived credentials. For hardware endpoints, the devices must use certificates to register with the session manager or multipoint controller.

If the Voice Video Endpoint used for videoconferencing does not electronically verify the CAC or derived credentials, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint used for videoconferencing to electronically verify the CAC or derived credentials.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7029r363842_chk'
  tag severity: 'medium'
  tag gid: 'V-206773'
  tag rid: 'SV-206773r604140_rule'
  tag stig_id: 'SRG-NET-000342-VVEP-00031'
  tag gtitle: 'SRG-NET-000342'
  tag fix_id: 'F-7029r363843_fix'
  tag 'documentable'
  tag legacy: ['SV-81235', 'V-66745']
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
end
