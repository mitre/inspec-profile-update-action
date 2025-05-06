control 'SV-220363' do
  title 'MarkLogic Server must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity.'
  desc 'check', 'Review DBMS settings to determine whether organizational users are uniquely identified and authenticated when logging on/connecting to the system.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the App Server to be checked resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. Select each of the App Servers.
5. Inspect the selected authentication method. If "application-level" is selected and a user other than "nobody" (or equivalent) is set as the default user, this is a finding.'
  desc 'fix', 'Configure MarkLogic settings to uniquely identify and authenticate all organizational users who log on/connect to the system.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the App Server to be checked resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. Select each of the App Servers.
5. Inspect the selected authentication method. If "application-level" is selected and a user other than "nobody" (or equivalent) is set as the default user, then change the default user to "nobody".'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22078r401540_chk'
  tag severity: 'medium'
  tag gid: 'V-220363'
  tag rid: 'SV-220363r622777_rule'
  tag stig_id: 'ML09-00-003500'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-22067r401541_fix'
  tag 'documentable'
  tag legacy: ['SV-110073', 'V-100969']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
