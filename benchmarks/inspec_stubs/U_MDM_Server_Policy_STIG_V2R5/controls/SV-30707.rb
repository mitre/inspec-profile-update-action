control 'SV-30707' do
  title 'The mobile device management (MDM) server administrator must receive required training.'
  desc 'The security posture of the MDM server could be compromised if the administrator is not trained to follow required procedures.'
  desc 'check', 'Detailed policy requirements: 
The MDM server administrator must be trained on the following requirements: 

- Requirement that administrative service accounts will not be used to log into the mobile device management server or any server service. 

- Activation passwords or PINs will consist of a pseudo-random pattern of at least eight characters consisting of at least two letters and two numbers. A new activation password must be selected each time one is assigned (e.g., the same password cannot be used for all users or for a group of users). 

- User and group accounts on the MDM server will always be assigned a STIG-compliant security/IT policy.

Check procedures: 
-Verify the MDM server administrator(s) has received the required training. The site should document when the training was completed.

If the MDM server administrator did not receive required training, this is a finding.'
  desc 'fix', 'Have MDM server administrator complete and document his/her training.'
  impact 0.3
  ref 'DPMS Target MDM Server Policy'
  tag check_id: 'C-31134r9_chk'
  tag severity: 'low'
  tag gid: 'V-24970'
  tag rid: 'SV-30707r7_rule'
  tag stig_id: 'WIR-WMSP-001-01'
  tag gtitle: 'MDM server administrator training'
  tag fix_id: 'F-27604r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
