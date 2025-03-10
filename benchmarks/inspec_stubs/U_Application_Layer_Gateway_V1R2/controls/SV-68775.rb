control 'SV-68775' do
  title 'The ALG providing user authentication intermediary services using PKI-based user authentication must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).

The intent of this requirement is to require support for a secondary certificate validation method using a locally cached revocation data, such as Certificate Revocation List (CRL), in case access to OCSP (required by CCI-000185) is not available. Based on a risk assessment, an alternate mitigation is to configure the system to deny access when revocation data is unavailable. 

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'If the ALG does not provide PKI-based user authentication intermediary services, this is not applicable.

Verify the ALG implements a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.

If the ALG does not implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network, this is a finding.'
  desc 'fix', 'If PKI-based user authentication intermediary services are provided, configure the ALG to implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55145r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54529'
  tag rid: 'SV-68775r1_rule'
  tag stig_id: 'SRG-NET-000345-ALG-000099'
  tag gtitle: 'SRG-NET-000345-ALG-000099'
  tag fix_id: 'F-59383r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
