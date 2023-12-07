control 'SV-38872' do
  title 'The system must use a separate file system for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine the location of the audit data path.

#more /etc/security/audit/config
Make note of the binfile and trail location.
(The best practice is to have the audit data and trails sent to /audit.)

# cd < audit path >
#df -k .

If the system audit data path is not on a separate file system, this is a finding.'
  desc 'fix', 'Migrate the system audit data path onto a separate file system.   

Update the /etc/security/audit/config file as necessary to reflect the location of the audit data.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37872r1_chk'
  tag severity: 'low'
  tag gid: 'V-23738'
  tag rid: 'SV-38872r1_rule'
  tag stig_id: 'GEN003623'
  tag gtitle: 'GEN003623'
  tag fix_id: 'F-33125r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
