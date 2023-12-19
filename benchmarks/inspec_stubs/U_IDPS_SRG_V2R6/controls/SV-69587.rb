control 'SV-69587' do
  title 'The IDPS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'Some ports, protocols, or services have known exploits or security weaknesses. These ports, protocols, and services must be prohibited or restricted in the IDPS configuration in accordance with DoD policy. 

Policy filters restrict traffic destined to the enclave perimeter in accordance with the guidelines contained in DoD Instruction 8551.1 for all ports, protocols, and functions.

System administrators will review the vulnerability assessment for each port allowed into the enclave and apply all appropriate mitigations defined in the Vulnerability Assessment report. Only ports, protocols, and functions allowed into the enclave should be registered in the PPSM database. It is the responsibility of the enclave owner to have the applications the enclave uses registered in the PPSM database.'
  desc 'check', 'Verify the IDPS is configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.

If the IDPS is not configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments, this is a finding.'
  desc 'fix', 'Configure the IDPS to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55963r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55341'
  tag rid: 'SV-69587r2_rule'
  tag stig_id: 'SRG-NET-000132-IDPS-00195'
  tag gtitle: 'SRG-NET-000132-IDPS-00195'
  tag fix_id: 'F-60207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
