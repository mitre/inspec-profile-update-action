control 'SV-246958' do
  title 'ONTAP must be configured to implement cryptographic mechanisms using FIPS 140-2.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

'
  desc 'check', 'Use "set -privilege advanced" reply "y" to continue and "security config show" to see if cluster FIPS mode is true.

If ONTAP cannot be configured to implement cryptographic mechanisms using FIPS 140-2, this is a finding.'
  desc 'fix', 'Configure ONTAP to use cryptographic mechanisms with "set -privilege advanced" reply "y" to continue and  "security config modify -is-fips-enabled true".'
  impact 0.7
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50390r769204_chk'
  tag severity: 'high'
  tag gid: 'V-246958'
  tag rid: 'SV-246958r769206_rule'
  tag stig_id: 'NAOT-MA-000002'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-50344r769205_fix'
  tag satisfies: ['SRG-APP-000412-NDM-000331', 'SRG-APP-000411-NDM-000330', 'SRG-APP-000179-NDM-000265']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-003123', 'CCI-002890']
  tag nist: ['IA-7', 'MA-4 (6)', 'MA-4 (6)']
end
