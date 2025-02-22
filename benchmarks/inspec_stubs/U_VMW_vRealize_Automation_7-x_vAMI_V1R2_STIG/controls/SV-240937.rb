control 'SV-240937' do
  title 'The vAMI must not contain any unnecessary functions and only provide essential capabilities.'
  desc 'Application servers provide a myriad of differing processes, features and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system. Application servers must provide the capability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance, for example, disabling dynamic JSP reloading on production application servers as a best practice.'
  desc 'check', 'Review the vAMI directories and files.

Determine if there are any tutorials, examples, or sample code.

If any tutorials, examples, or sample code is present, this is a finding.'
  desc 'fix', 'Remove all tutorials, examples, and sample code.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44170r675976_chk'
  tag severity: 'high'
  tag gid: 'V-240937'
  tag rid: 'SV-240937r879587_rule'
  tag stig_id: 'VRAU-VA-000185'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-44129r675977_fix'
  tag 'documentable'
  tag legacy: ['SV-100867', 'V-90217']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
