control 'SV-230785' do
  title 'The macOS system must accept and verify Personal Identity Verification (PIV) credentials, implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network, and only allow the use of DoD PKI-established certificate authorities to verify the establishment of protected sessions.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.                                                      

Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).                                       

Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.             

The DoD will only accept PKI-certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.

'
  desc 'check', 'To verify that certificate checks are occurring, run the following command.

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep checkCertificateTrust

If the output is null or the value returned, "checkCertificateTrust = 1", is not equal to (1) or greater,  this is a finding.'
  desc 'fix', 'This setting is enforced using the "Smart Card Policy" configuration profile. 

Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33730r607242_chk'
  tag severity: 'medium'
  tag gid: 'V-230785'
  tag rid: 'SV-230785r599842_rule'
  tag stig_id: 'APPL-11-001060'
  tag gtitle: 'SRG-OS-000376-GPOS-00161'
  tag fix_id: 'F-33703r607243_fix'
  tag satisfies: ['SRG-OS-000376-GPOS-00161', 'SRG-OS-000377-GPOS-00162', 'SRG-OS-000384-GPOS-00167', 'SRG-OS-000403-GPOS-00182', 'SRG-OS-000067-GPOS-00035']
  tag 'documentable'
  tag cci: ['CCI-000186', 'CCI-001991', 'CCI-001953', 'CCI-001954', 'CCI-002470']
  tag nist: ['IA-5 (2) (a) (1)', 'IA-5 (2) (d)', 'IA-2 (12)', 'IA-2 (12)', 'SC-23 (5)']
end
