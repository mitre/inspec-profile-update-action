control 'SV-206772' do
  title 'The Voice Video Endpoint used for videoconferencing must accept a Common Access Card (CAC) or derived credentials.'
  desc 'The use of CAC or derived credentials facilitates standardization and reduces the risk of unauthorized access. DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'If the Voice Video Endpoint is a hardware endpoint, this check procedure is Not Applicable.

Verify the Voice Video Endpoint used for videoconferencing accepts a CAC or derived credentials. For hardware endpoints, the devices must use certificates to register with the session manager or multipoint controller.

If the Voice Video Endpoint used for videoconferencing does not accept a CAC or derived credentials, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint used for videoconferencing to accept a CAC or derived credentials.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7028r363839_chk'
  tag severity: 'medium'
  tag gid: 'V-206772'
  tag rid: 'SV-206772r604140_rule'
  tag stig_id: 'SRG-NET-000341-VVEP-00030'
  tag gtitle: 'SRG-NET-000341'
  tag fix_id: 'F-7028r363840_fix'
  tag 'documentable'
  tag legacy: ['SV-81233', 'V-66743']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
