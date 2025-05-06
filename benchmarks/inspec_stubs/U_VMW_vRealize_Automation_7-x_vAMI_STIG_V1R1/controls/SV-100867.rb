control 'SV-100867' do
  title 'The vAMI must not contain any unnecessary functions and only provide essential capabilities.'
  desc 'Application servers provide a myriad of differing processes, features and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system. Application servers must provide the capability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance, for example, disabling dynamic JSP reloading on production application servers as a best practice.'
  desc 'check', 'Review the vAMI directories and files.

Determine if there are any tutorials, examples, or sample code.

If any tutorials, examples, or sample code is present, this is a finding.'
  desc 'fix', 'Remove all tutorials, examples, and sample code.'
  impact 0.7
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89909r1_chk'
  tag severity: 'high'
  tag gid: 'V-90217'
  tag rid: 'SV-100867r1_rule'
  tag stig_id: 'VRAU-VA-000185'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-96959r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
