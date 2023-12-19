control 'SV-18871' do
  title 'inadequate user training for pc presentation sharing that could lead to compromise of other information on the presenting PC'
  desc 'Users must be trained regarding the display of information that is not part of the conference. 
Such training must be based on the SOP discussed under RTS-VTC 2440.01 that is designed to mitigate the vulnerability.'
  desc 'check', '[IP][ISDN]; Interview the IAO to validate compliance with the following requirement:

Ensure VTU users receive training in the proper use and operation of PC to CODEC connections and understand the vulnerabilities associated with such interconnections regarding inadvertent or improper information disclosure.

Interview a sampling of VTU administrators and users to verify that training has been provided for proper use and operation of PC to CODEC connections and that they understand the vulnerabilities associated with such interconnections regarding inadvertent or improper information disclosure. This is a finding if deficiencies are found. List these deficiencies in the finding details.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
Train users and administrators in the proper use and operation of PC to CODEC connections and provide an understanding of  the vulnerabilities associated with such interconnections regarding inadvertent or improper information disclosure.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17697'
  tag rid: 'SV-18871r1_rule'
  tag stig_id: 'RTS-VTC 2460.00'
  tag gtitle: 'RTS-VTC 2460.00 [IP][ISDN]'
  tag fix_id: 'F-17594r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'DCBP-1, ECSC-1, PRTN-1'
end
