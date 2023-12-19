control 'SV-233201' do
  title 'The container platform, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'The potential of allowing access to users who are no longer authorized  (have revoked certificates) increases unless a local cache of revocation data is configured.'
  desc 'check', 'Review the container platform configuration.

 If the container platform is not implemented to use a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network, this is a finding.'
  desc 'fix', 'Configure the container platform to implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36137r601805_chk'
  tag severity: 'medium'
  tag gid: 'V-233201'
  tag rid: 'SV-233201r601806_rule'
  tag stig_id: 'SRG-APP-000401-CTR-000965'
  tag gtitle: 'SRG-APP-000401'
  tag fix_id: 'F-36105r601091_fix'
  tag 'documentable'
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
