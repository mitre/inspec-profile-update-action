control 'SV-248725' do
  title 'The OL 8 Information System Security Officer (ISSO) and System Administrator (SA) (at a minimum) must have mail aliases to be notified of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 
 
Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. 
 
This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Verify the administrators are notified in the event of an audit processing failure. 
 
Check that the "/etc/aliases" file has a defined value for "root". 
 
$ sudo grep "postmaster:\\s*root$" /etc/aliases 

postmaster:  root

If the command does not return a line or the line is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to notify administrators in the event of an audit processing failure. 
 
Add/update the following line in "/etc/aliases": 
 
postmaster: root'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52159r779739_chk'
  tag severity: 'medium'
  tag gid: 'V-248725'
  tag rid: 'SV-248725r779741_rule'
  tag stig_id: 'OL08-00-030030'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-52113r779740_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
