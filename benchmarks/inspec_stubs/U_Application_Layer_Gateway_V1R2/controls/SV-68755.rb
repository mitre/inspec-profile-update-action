control 'SV-68755' do
  title 'The ALG providing user authentication intermediary services must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc "To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.
Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following.

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication.

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement applies to ALGs that provide user proxy services, including identification and authentication. This service must use the site's directory service (e.g., Active Directory). Directory services must not be installed onto the gateway."
  desc 'check', 'If the ALG does not provide user authentication intermediary services, this is not applicable.

Verify the ALG uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

If the ALG does not uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users), this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55125r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54509'
  tag rid: 'SV-68755r1_rule'
  tag stig_id: 'SRG-NET-000138-ALG-000063'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag fix_id: 'F-59363r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
