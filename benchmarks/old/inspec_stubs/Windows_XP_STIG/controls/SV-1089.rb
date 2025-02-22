control 'SV-1089' do
  title 'The required legal notice must be configured to display before console logon.'
  desc 'Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options ->“Interactive Logon: Message text for users attempting to log on” as outlined in the check.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1089'
  tag rid: 'SV-1089r3_rule'
  tag gtitle: 'Legal Notice Display'
  tag fix_id: 'F-28804r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECWM-1'
end
