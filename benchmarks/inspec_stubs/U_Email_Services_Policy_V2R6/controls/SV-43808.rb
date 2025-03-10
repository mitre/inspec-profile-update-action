control 'SV-43808' do
  title 'Email acceptable use policy must be renewed annually.'
  desc 'An Email Acceptable Use Policy is a set of rules that describe IA operation and expected user behavior with regard to email services. Formal creation and use of an Email Acceptable Use policy protects both organization and users by declaring boundaries, operational processes, and user training surrounding helpdesk procedures, legal constraints and email based threats that may be encountered. 

The Email Acceptable Use Policy must be annually updated, then subject to renewal by users. Requiring signed acknowledgement of the policy would constitute continued access to the email system.'
  desc 'check', 'Access the EDSP documentation that describes the Email Acceptable Use Policy. Verify there is a stated requirement for users to renew annually. 

If the Email Acceptable Use Policy requires annual user renewal with signature acknowledgement, this is not a finding.'
  desc 'fix', 'Implement a review and renewal process for the Email Acceptable Use Policy that requires annual renewal and signature acknowledgement.  Document the process in the EDSP.'
  impact 0.3
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-41596r2_chk'
  tag severity: 'low'
  tag gid: 'V-33389'
  tag rid: 'SV-43808r2_rule'
  tag stig_id: 'EMG0-093 EMail'
  tag gtitle: 'EMG0-093 Email Acceptable Use Policy'
  tag fix_id: 'F-37315r2_fix'
  tag 'documentable'
  tag responsibility: 'Other'
end
