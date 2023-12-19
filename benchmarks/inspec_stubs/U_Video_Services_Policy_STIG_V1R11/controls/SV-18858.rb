control 'SV-18858' do
  title 'The VTU must use FIPS 140-2 validated encryption module.'
  desc 'The current DoD requirement for commercial grade encryption is that the encryption module, which includes a FIPS 197 validated encryption algorithm plus approved functions (i.e., key management and sharing/distribution functions), be NIST validated to FIPS 140-2. It must be noted that legacy equipment validated to FIPS 140-1 may still be used and FIPS 140-3 is in development.

While many VTU vendors support AES, they have only validated the algorithm to FIPS-197, if at all. This does not meet the FIPS 140-2 requirement because the additional approved functions have not been addressed.'
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement: 

Ensure VTUs under his/her control employ encryption module(s) validated to FIPS 140-2.

Determine if the various VTUs with which the system under review is expected to communicate support and are using FIPS 140-2 validated encryption modules and that they are operated in FIPS mode. Have the ISSO or SA demonstrate and verify that the VTU is using 140-2 encryption in FIPS mode. Review documentation from the vendor designating the encryption modules in use and verify that they are listed on the NIST CMVP validated modules web site (http://csrc.nist.gov/groups/STM/cmvp/validation.html). If the VTU does not use FIPS 140-2 validated encryption module, this is a finding.'
  desc 'fix', 'Purchase and install only those VTUs and MCUs that employ encryption modules that are validated to FIPS 140-2 standards. Upgrade or replace non-compliant devices.

Note: Updating firmware or software to provide desired functionality is preferred. A vendor may provide security updates and patches that offer additional functions. In many cases, the IA Vulnerability Management (IAVM) system mandates updating software to reduce risk to DoD networks.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18954r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17684'
  tag rid: 'SV-18858r2_rule'
  tag stig_id: 'RTS-VTC 1230.00'
  tag gtitle: 'RTS-VTC 1230'
  tag fix_id: 'F-17581r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'For APL testing and new installations of new (non-legacy) equipment, this finding can be reduced to a CAT III in the event the crypto module in use is in the FIPS validation process as listed on the NIST CMVP modules in Process web site. http://csrc.nist.gov/groups/STM/cmvp/inprocess.html. The POAM for closing the finding must indicate the expected date that the module will achieve validation and the process to ensure the module in use is the validated module.'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECCT-1, ECNK-1, ECSC-1'
end
