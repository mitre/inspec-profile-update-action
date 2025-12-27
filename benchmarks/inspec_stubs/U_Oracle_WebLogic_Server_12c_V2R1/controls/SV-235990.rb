control 'SV-235990' do
  title 'Oracle WebLogic must limit the use of resources by priority and not impede the host from servicing processes designated as a higher-priority.'
  desc 'Priority protection helps the application server prevent a lower-priority application process from delaying or interfering with any higher-priority application processes. If the application server is not capable of managing application resource requests, the application server could become overwhelmed by a high volume of low-priority resource requests which can cause an availability issue.

This requirement only applies to Mission Assurance Category 1 systems and does not apply to information systems with a Mission Assurance Category of 2 or 3.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Work Managers' 
3. Existing Work Managers will appear in the list

If Work Managers are not created to allow prioritization of resources, this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Work Managers' 
3. Utilize 'Change Center' to create a new change session 
4. Click 'New', select 'Work Manager' radio option, click 'Next'
5. Type a unique name, click 'Next', select server(s) which to apply this work manager to, click 'Finish'
6. Select newly created work manager from table to configure
7. Set thread and capacity constraints for this work manager, target the server(s) to apply these constraints to, click 'Save'
8. Deploy applications requiring prioritization to the server(s) selected as target of the work manager in order to apply the priority conditions specified by the work manager to deployed applications"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39209r628746_chk'
  tag severity: 'medium'
  tag gid: 'V-235990'
  tag rid: 'SV-235990r628748_rule'
  tag stig_id: 'WBLC-08-000237'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-39172r628747_fix'
  tag 'documentable'
  tag legacy: ['SV-70595', 'V-56341']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
