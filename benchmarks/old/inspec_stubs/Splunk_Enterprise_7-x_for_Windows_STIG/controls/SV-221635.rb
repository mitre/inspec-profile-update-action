control 'SV-221635' do
  title 'Splunk Enterprise must prohibit password reuse for a minimum of five generations for the account of last resort.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

To meet password policy requirements, passwords need to be changed at specific policy-based intervals.

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.

In most enterprise environments, this requirement is usually mitigated by a properly configured external authentication system, like LDAP. Splunk local authentication takes precedence over other forms of authentication, and cannot be disabled. The mitigation settings in this requirement apply in the event a local account gets created, for example, an emergency account of last resort for recovery.'
  desc 'check', 'Select Settings >> Access Controls >> Password Policy Management and verify that History is Enabled and Password history count is set to 5 or more.

If not set to 5 or more, this is a finding.'
  desc 'fix', 'Select Settings >> Access Controls >> Password Policy Management and set History to Enabled and Password history count to 5 or more.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23350r416362_chk'
  tag severity: 'low'
  tag gid: 'V-221635'
  tag rid: 'SV-221635r879602_rule'
  tag stig_id: 'SPLK-CL-000390'
  tag gtitle: 'SRG-APP-000165-AU-002580'
  tag fix_id: 'F-23339r416363_fix'
  tag 'documentable'
  tag legacy: ['SV-111361', 'V-102417']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
