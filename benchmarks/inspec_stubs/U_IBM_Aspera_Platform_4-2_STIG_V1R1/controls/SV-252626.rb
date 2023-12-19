control 'SV-252626' do
  title 'The IBM Aspera High-Speed Transfer Endpoint must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If the cached authenticator information is out of date, the validity of the authentication information may be questionable.

This requirement applies to all ALGs that may cache user authenticators for use throughout a session. It also applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', %q(Verify the IBM Aspera High-Speed Transfer Endpoint prohibits the use of cached authenticators after an organization-defined time period with the following command:

$ sudo /opt/aspera/bin/asuserdata -a | grep 'token_life'

token_life_seconds: "86400"

Note: The example token life is for one day; this number must be defined by the organization.

If no result is returned or if the result is not an organization-defined time period, this is a finding.)
  desc 'fix', 'Configure the IBM Aspera High-Speed Transfer Endpoint to prohibit the use of cached authenticators after an organization-defined time period with the following command:

$ sudo /opt/aspera/bin/asconfigurator -x "set_node_data;token_life_seconds,86400"

Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56082r818046_chk'
  tag severity: 'medium'
  tag gid: 'V-252626'
  tag rid: 'SV-252626r818048_rule'
  tag stig_id: 'ASP4-TE-030240'
  tag gtitle: 'SRG-NET-000344-ALG-000098'
  tag fix_id: 'F-56032r818047_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
