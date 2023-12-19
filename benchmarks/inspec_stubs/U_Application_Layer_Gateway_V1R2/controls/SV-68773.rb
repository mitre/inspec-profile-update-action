control 'SV-68773' do
  title 'The ALG must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If the cached authenticator information is out of date, the validity of the authentication information may be questionable.

This requirement applies to all ALGs which may cache user authenticators for use throughout a session. This requirement also applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'Verify the ALG prohibits the use of cached authenticators after an organization-defined time period.

If the ALG does not prohibit the use of cached authenticators after an organization-defined time period, this is a finding.'
  desc 'fix', 'Configure the ALG to prohibit the use of cached authenticators after an organization-defined time period.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55143r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54527'
  tag rid: 'SV-68773r1_rule'
  tag stig_id: 'SRG-NET-000344-ALG-000098'
  tag gtitle: 'SRG-NET-000344-ALG-000098'
  tag fix_id: 'F-59381r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
