control 'SV-222553' do
  title 'The application, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'A local cache of revocation data is also known as a CRL list. This list contains a list of revoked certificates and can be periodically downloaded to ensure certificates can still be checked for revocation when network access is not available or access to the Online Certificate Status Protocol OCSP server is not available.

Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).'
  desc 'check', 'Review the application documentation and interview the system administrator to identify how the application checks certificate revocation.

If the application resides on the SIPRNET and does not have access to the root CAs this requirement is not applicable.

Different application frameworks may handle this requirement for the developer or the developer may have chosen to implement their own implementation for managing and implementing the CRL.

Have the administrator demonstrate the process used for obtaining and importing the CRL. CAs may publish the CRL in an LDAP directory or it may be posted to an HTTP server.

Verify the application is configured to import the CRL on a regular basis.

Have the administrator demonstrate the configuration setting that enables CRL checking in the event the OCSP server is not available.

If the application is not configured to implement a CRL, this is a finding.'
  desc 'fix', 'Implement a Certificate Revocation List (CRL) import process and configure the application to check the CRL if OCSP is not available.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24223r493567_chk'
  tag severity: 'medium'
  tag gid: 'V-222553'
  tag rid: 'SV-222553r879774_rule'
  tag stig_id: 'APSC-DV-001840'
  tag gtitle: 'SRG-APP-000401'
  tag fix_id: 'F-24212r493568_fix'
  tag 'documentable'
  tag legacy: ['SV-84777', 'V-70155']
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
