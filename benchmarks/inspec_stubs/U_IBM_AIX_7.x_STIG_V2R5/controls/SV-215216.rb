control 'SV-215216' do
  title 'AIX must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. AIX must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

OpenSSL FIPS object module is a cryptographic module that is designed to meet the requirements for FIPS 140-2 validation by CMVP and is compatible with OpenSSL libraries. The 2.0.13 FIPS object module version has been FIPS validated and certified by CMVP for multiple AIX versions on Power 7 and Power 8 platforms under certificate #2398.

IBM has released a FIPS capable OpenSSL (Fileset VRMF: 20.13.102.1000), which is OpenSSL 1.0.2j version with 2.0.13 object module. The fileset is available in Web Download Pack.


'
  desc 'check', 'Run the following command to determine the version of OpenSSL that is installed:

# lslpp -l | grep -i openssl
 openssl.base             20.13.704.1776  COMMITTED  Open Secure Socket Layer

If the OpenSSL version is older than "20.13.102.1000", this is a finding.'
  desc 'fix', 'Use the following command to uninstall the old version of OpenSSL that is not FIPS 140-2 certified, then install OpenSSL VRMF 20.13.102.1000:
# smitty install'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16414r294099_chk'
  tag severity: 'medium'
  tag gid: 'V-215216'
  tag rid: 'SV-215216r517598_rule'
  tag stig_id: 'AIX7-00-001108'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-16412r294100_fix'
  tag satisfies: ['SRG-OS-000120-GPOS-00061', 'SRG-OS-000478-GPOS-00223', 'SRG-OS-000396-GPOS-00176']
  tag 'documentable'
  tag legacy: ['SV-101663', 'V-91565']
  tag cci: ['CCI-000803', 'CCI-002450']
  tag nist: ['IA-7', 'SC-13 b']
end
