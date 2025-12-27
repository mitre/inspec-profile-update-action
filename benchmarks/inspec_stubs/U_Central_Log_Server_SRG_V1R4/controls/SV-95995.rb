control 'SV-95995' do
  title 'The Central Log Server must be configured to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses.'
  desc 'check', 'Examine the configuration.

Verify that individual user accounts are defined within the application. Each account must have a separate identifier. If an authentication server may be used for login, ensure the application audit logs containing management and configuration actions, identify the individual performing each action.

If the Central Log Server is not configured to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users), this is a finding.'
  desc 'fix', 'For systems where individual users access, configure and/or manage the system, configure the Central Log Server application so each user is explicitly identified and authenticated. While an authentication server, is often used for logon, this requirement must include instructions for integrating the authentication server so that they system requires unique identification and authentication.

Note: Group accounts are not permitted for logon to the Central Log Server.'
  impact 0.7
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80981r1_chk'
  tag severity: 'high'
  tag gid: 'V-81281'
  tag rid: 'SV-95995r1_rule'
  tag stig_id: 'SRG-APP-000148-AU-002270'
  tag gtitle: 'SRG-APP-000148-AU-002270'
  tag fix_id: 'F-88063r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
