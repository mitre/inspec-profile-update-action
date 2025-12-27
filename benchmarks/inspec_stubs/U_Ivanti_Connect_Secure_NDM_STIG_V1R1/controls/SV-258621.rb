control 'SV-258621' do
  title 'The ICS must be configured to generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'In the ICS Web UI, navigate to System >> Log/Monitoring >> Admin Access >> Settings.

1. Under the section "Select Events to Log", verify "Administrator Logins" is checked.

If the ICS is not configured to generate audit records when successful/unsuccessful attempts to access privileges occur, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to System >> Log/Monitoring >> Admin Access >> Settings.
1. Check the box under the section "Select Events to Log" for "Administrator Logins".
2. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62361r930549_chk'
  tag severity: 'medium'
  tag gid: 'V-258621'
  tag rid: 'SV-258621r930551_rule'
  tag stig_id: 'IVCS-NM-000510'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-62270r930550_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
