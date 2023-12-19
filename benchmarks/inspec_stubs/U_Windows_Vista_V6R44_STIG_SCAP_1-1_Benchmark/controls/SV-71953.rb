control 'SV-71953' do
  title 'The system must be configured to attempt to forward queued error reports once a day.'
  desc 'Error reports stored in the queue should be forwarded to a local or DOD-wide collection site when the system can connect to the site.  This setting controls the frequency a system will use to try forwarding queued reports to the local or DOD-wide collector.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Queue" to "Enabled" with "Number of days between solution check reminders:" set to "1".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-57475'
  tag rid: 'SV-71953r1_rule'
  tag stig_id: 'WINER-000016'
  tag gtitle: 'WINER-000016'
  tag fix_id: 'F-62749r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
