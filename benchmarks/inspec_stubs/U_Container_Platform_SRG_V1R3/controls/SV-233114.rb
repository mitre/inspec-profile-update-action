control 'SV-233114' do
  title 'The container platform must separate user functionality (including user interface services) from information system management functionality.'
  desc 'Separating user functionality from management functionality is a requirement for all the components within the container platform. Without the separation, users may have access to management functions that can degrade the container platform and the services being offered and can offer a method to bypass testing and validation of functions before introduced into a production environment.

The separation should be enforced by each component within the container platform.'
  desc 'check', 'Review the container platform configuration to determine if management functionality is separated from user functionality. 

Validate that the separation is also implemented within the components by trying to execute management functions for each component as a user. 

If the container platform is not configured to separate management and user functionality or if component management and user functionality are not separated, this is a finding.'
  desc 'fix', 'Configure the container platform and its components to separate management and user functionality.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36050r601742_chk'
  tag severity: 'medium'
  tag gid: 'V-233114'
  tag rid: 'SV-233114r601743_rule'
  tag stig_id: 'SRG-APP-000211-CTR-000530'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-36018r600830_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
