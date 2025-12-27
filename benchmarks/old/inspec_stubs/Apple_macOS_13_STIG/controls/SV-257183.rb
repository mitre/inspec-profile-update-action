control 'SV-257183' do
  title 'The macOS system must accept and verify Personal Identity Verification (PIV) credentials, implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network, and only allow the use of DOD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).

Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

DOD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.

The DOD will only accept PKI certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.

'
  desc 'check', 'Verify the macOS system is configured to check the revocation status of user certificates with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "checkCertificateTrust"

checkCertificateTrust = 1;

If there is no result, or if "checkCertificateTrust" is not set to "1" or greater, this is a finding.'
  desc 'fix', 'Configure the macOS system to check the revocation status of user certificates by installing the "Smart Card Policy" configuration profile. 

Note: To ensure continued access to the operating system, consult the supplemental guidance provided with the STIG before applying the "Smart Card Policy".'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60868r905180_chk'
  tag severity: 'medium'
  tag gid: 'V-257183'
  tag rid: 'SV-257183r905182_rule'
  tag stig_id: 'APPL-13-001060'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-60809r905181_fix'
  tag satisfies: ['SRG-OS-000067-GPOS-00035', 'SRG-OS-000376-GPOS-00161', 'SRG-OS-000377-GPOS-00162', 'SRG-OS-000384-GPOS-00167', 'SRG-OS-000403-GPOS-00182']
  tag 'documentable'
  tag cci: ['CCI-000186', 'CCI-001953', 'CCI-001954', 'CCI-001991', 'CCI-002470']
  tag nist: ['IA-5 (2) (a) (1)', 'IA-2 (12)', 'IA-2 (12)', 'IA-5 (2) (d)', 'SC-23 (5)']
end
