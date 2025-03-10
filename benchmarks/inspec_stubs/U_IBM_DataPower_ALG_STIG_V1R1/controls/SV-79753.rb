control 'SV-79753' do
  title 'The DataPower Gateway must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If the cached authenticator information is out of date, the validity of the authentication information may be questionable.

This requirement applies to all ALGs which may cache user authenticators for use throughout a session. This requirement also applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'Search Bar “AAA Policy” >> Select AAA Policy. If no AAA Policy is present, this is a finding.

Search Bar “AAA Policy” >> Select AAA Policy >> AAA policy >> Authentication. If cache authentication results “Disabled”, this is a finding.

Search Bar “Processing Policy” >> processing policy >> Policy Maps tab processing rule >> Rule Action. If no AAA action exists, this is a finding.'
  desc 'fix', 'Search Bar “AAA Policy” >> Select AAA Policy >> AAA policy >> Authentication >> Cache authentication results “Absolute” or “Maximum” or “Minimum” >> Cache Lifetime cache value.

Search Bar “Processing Policy” >> processing policy >> Policy Maps tab processing rule >> Processing Rule processing rule >> Rule Action AAA policy'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65263'
  tag rid: 'SV-79753r1_rule'
  tag stig_id: 'WSDP-AG-000095'
  tag gtitle: 'SRG-NET-000344-ALG-000098'
  tag fix_id: 'F-71203r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
