control 'SV-216984' do
  title 'The router must be configured to use keys with a duration not exceeding 180 days for authenticating routing protocol messages.'
  desc 'If the keys used for routing protocol authentication are guessed, the malicious user could create havoc within the network by advertising incorrect routes and redirecting traffic. Some routing protocols allow the use of key chains for authentication. A key chain is a set of keys that is used in succession, with each having a lifetime of no more than 180 days. Changing the keys frequently reduces the risk of them eventually being guessed.

Keys cannot be used during time periods for which they are not activated. If a time period occurs during which no key is activated, neighbor authentication cannot occur, and therefore routing updates will fail. Therefore, ensure that for a given key chain, key activation times overlap to avoid any period of time during which no key is activated.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

For each authenticated routing protocol session, review the configured key expiration dates.

If any key has a lifetime of more than 180 days, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

For each authenticated routing protocol session, configure each key to have a lifetime of no more than 180 days.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-18214r382658_chk'
  tag severity: 'medium'
  tag gid: 'V-216984'
  tag rid: 'SV-216984r604135_rule'
  tag stig_id: 'SRG-NET-000230-RTR-000003'
  tag gtitle: 'SRG-NET-000230'
  tag fix_id: 'F-18212r382659_fix'
  tag 'documentable'
  tag legacy: ['SV-70013', 'V-55759']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
