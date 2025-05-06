control 'SV-76889' do
  title 'ColdFusion must limit applications from changing shared Java components.'
  desc 'Application servers have the ability to specify that the hosted applications utilize shared libraries.  Within ColdFusion, these shared libraries are often Java components along with server settings.  By allowing programmers or attackers to write CFML code that can directly access these components and settings, the programmer can change how shared Java components work and create new Java components.  By disabling this option, the programmer is unable to read or modify administration and configuration information for the server and shared Java components.'
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

If "Disable access to internal ColdFusion Java components" is unchecked, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.   Check "Disable access to internal ColdFusion Java components" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63203r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62399'
  tag rid: 'SV-76889r1_rule'
  tag stig_id: 'CF11-03-000091'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag fix_id: 'F-68319r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
