control 'SV-79755' do
  title 'The DataPower Gateway providing user authentication intermediary services using PKI-based user authentication must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).

The intent of this requirement is to require support for a secondary certificate validation method using a locally cached revocation data, such as Certificate Revocation List (CRL), in case access to OCSP (required by CCI-000185) is not available. Based on a risk assessment, an alternate mitigation is to configure the system to deny access when revocation data is unavailable. 

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'Search Bar “AAA Policy” >> Select AAA Policy. If no AAA Policy is present, this is a finding.

Search Bar “AAA Policy” >> Select AAA Policy >> AAA policy >> Authentication. If cache authentication results “Disabled”, this is a finding.

Search Bar “Processing Policy” >> processing policy >> Policy Maps tab processing rule >> Rule Action. If no AAA action exists, this is a finding.'
  desc 'fix', 'Search Bar “AAA Policy” >> Select AAA Policy >> AAA policy >> Authentication >> Cache authentication results “Absolute” or “Maximum” or “Minimum” >> Cache Lifetime cache value.

Search Bar “Processing Policy” >> processing policy >> Policy Maps tab processing rule >> Processing Rule processing rule >> Rule Action AAA policy'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65265'
  tag rid: 'SV-79755r1_rule'
  tag stig_id: 'WSDP-AG-000096'
  tag gtitle: 'SRG-NET-000345-ALG-000099'
  tag fix_id: 'F-71205r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
