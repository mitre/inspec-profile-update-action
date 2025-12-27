control 'SV-104251' do
  title 'Symantec ProxySG providing user authentication intermediary services using PKI-based user authentication must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).

The intent of this requirement is to require support for a secondary certificate validation method using a locally cached revocation data, such as Certificate Revocation List (CRL), in case access to OCSP (required by CCI-000185) is not available. Based on a risk assessment, an alternate mitigation is to configure the system to deny access when revocation data is unavailable. 

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'Verify that PKI Certificate Revocation Lists have been configured.

1. Log on to the Web Management Console.
2. Browse to Configuration >> SSL >> CRLs.
3. Verify that at least one CRL has been defined.

If Symantec ProxySG providing user authentication intermediary services using PKI-based user authentication does not implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network, this is a finding.'
  desc 'fix', 'Configure PKI Certificate Revocation lists.

1. Log on to the Web Management Console.
2. Browse to Configuration >> SSL >> CRLs.
3. Click "New" and configure in accordance the setting required by site guidance.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93483r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94297'
  tag rid: 'SV-104251r1_rule'
  tag stig_id: 'SYMP-AG-000420'
  tag gtitle: 'SRG-NET-000345-ALG-000099'
  tag fix_id: 'F-100413r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
