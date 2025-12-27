control 'SV-222522' do
  title 'The application must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). 

Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Review the application documentation and interview the application administrator to determine how organizational users access the application.

If the application is publicly available, providing access to publicly releasable data and the users are non-organizational users such as individuals who no longer have a CAC (e.g., retirees) or  members of the public with no requirement for DoD credentials, this requirement is not applicable.

The requirement still applies to DoD organizational users and admins when accessing the non-public data areas or system resources of the system.

Attempt to access the application and confirm that a unique user account and password or CAC token and pin are required in order to access the application.

If the application does not uniquely identify and authenticate users, this is a finding.'
  desc 'fix', 'Configure the application to uniquely identify and authenticate users and user processes.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24192r493474_chk'
  tag severity: 'high'
  tag gid: 'V-222522'
  tag rid: 'SV-222522r508029_rule'
  tag stig_id: 'APSC-DV-001540'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-24181r493475_fix'
  tag 'documentable'
  tag legacy: ['V-69527', 'SV-84149']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
