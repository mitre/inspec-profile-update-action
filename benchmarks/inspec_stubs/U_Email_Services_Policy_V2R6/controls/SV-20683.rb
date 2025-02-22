control 'SV-20683' do
  title 'Email acceptable use policy must be documented in the Email Domain Security Plan (EDSP).'
  desc 'Email is only as secure as the recipient, which is ultimately person who is receiving messages. Also to consider, the surest way to prevent SPAM and other malware from entering the email message transport path is by using secure IA measures at the point of origin. Here again, this is ultimately a person, who is sending messages. 

An Email Acceptable Use Policy is a set of rules that describe expected user behavior with regard to email messages. Formal creation and use of an Email Acceptable Use policy protects both organization and users by declaring boundaries, operational processes, and user training for such tasks as Help Desk procedures, legal considerations and email based threats that may be encountered. 

The Email Acceptable Use Policy should be distributed to and signed by each email user, as a requirement for obtaining an email account.'
  desc 'check', 'Access the EDSP documentation that describes the Email Acceptable Use Policy that is followed at the site. 

If the Email Acceptable Use Policy is documented in the EDSP, this is not a finding.'
  desc 'fix', 'Implement an Email Acceptable Use Policy that is documented in the EDSP and that requires a signature by each user.'
  impact 0.3
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22539r3_chk'
  tag severity: 'low'
  tag gid: 'V-18885'
  tag rid: 'SV-20683r3_rule'
  tag stig_id: 'EMG0-090 EMail'
  tag gtitle: 'EMG0-090 Email Acceptable Use Policy'
  tag fix_id: 'F-19581r3_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'PRRB-1'
end
