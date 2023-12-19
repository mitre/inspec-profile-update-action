control 'SV-82821' do
  title 'The Mainframe Product must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable. 

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account configurations. 

If the Mainframe Product does not uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users), this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68331'
  tag rid: 'SV-82821r1_rule'
  tag stig_id: 'SRG-APP-000148-MFP-000206'
  tag gtitle: 'SRG-APP-000148-MFP-000206'
  tag fix_id: 'F-74445r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
