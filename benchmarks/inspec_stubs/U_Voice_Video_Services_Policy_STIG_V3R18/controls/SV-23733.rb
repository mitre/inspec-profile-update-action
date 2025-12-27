control 'SV-23733' do
  title 'Unnecessary PPS have not been disabled or removed from VVoIP system devices or servers.'
  desc 'The availability of applications and services that are not necessary for the OAM&P of the VVoIP system’s devices and servers, running or not as well as the existence of their code, places them at risk of being attacked and these avenues exploited. As such they should be removed if possible or minimally disabled so they cannot run and be exploited.

For VVoIP and UC servers and endpoints, remove the software for or minimally disable PPS that are not necessary for the operation or maintenance of the system. Limit production PPS to production interfaces and management PPS to the OAM&P interfaces.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement: 

For VVoIP and UC servers and endpoints, ensure all PPS that are not necessary for the operation or maintenance of the system are disabled or the supporting software removed. Limit production PPS to production interfaces and management PPS to the OAM&P interfaces.'
  desc 'fix', 'Disable all PPS on all VVoIP or UC system servers and sevices that are not required to support OAM&P in the specific VVoIP system implementation. Additionally, if possible, remove the software for the unnecessary PPS.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-25777r1_chk'
  tag severity: 'medium'
  tag gid: 'V-21521'
  tag rid: 'SV-23733r1_rule'
  tag stig_id: 'VVoIP 1021 (GENERAL)'
  tag gtitle: 'Deficient Security: Unnecessary PPS disablement'
  tag fix_id: 'F-22312r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag responsibility: 'Information Assurance Officer'
end
