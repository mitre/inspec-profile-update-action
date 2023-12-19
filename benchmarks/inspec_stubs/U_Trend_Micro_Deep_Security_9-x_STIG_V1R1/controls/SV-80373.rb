control 'SV-80373' do
  title 'Trend Deep Security must provide the capability for authorized users to capture, record, and log all content related to a user session.'
  desc 'Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered. 

This requirement does not apply to applications that do not have a concept of a user session (e.g., calculator).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the capability for authorized users to capture, record, and log all content related to a user session is provided.

Verify the following events within the Administration >> System Settings >> System Events, are set to “Record.”
600 User Signed In
601 User Signed Out
602 User Timed Out
603 User Locked Out
608 User Session Validation Failed
610 User Session Validated

If these settings are not set to “Record”, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to provide the capability for authorized users to capture, record, and log all content related to a user session.

Go to Administration >> System Settings >> System Events, and set the following settings to “Record.”
600 User Signed In
601 User Signed Out
602 User Timed Out
603 User Locked Out
608 User Session Validation Failed
610 User Session Validated'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66531r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65883'
  tag rid: 'SV-80373r1_rule'
  tag stig_id: 'TMDS-00-000080'
  tag gtitle: 'SRG-APP-000093'
  tag fix_id: 'F-71959r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end
