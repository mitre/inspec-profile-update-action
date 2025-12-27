control 'SV-86189' do
  title 'The CA API Gateway must generate audit records showing starting and ending time for administrator access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Confirm the CA API Gateway file "/etc/audit/audit.rules" is the file as distributed using command:

rpm -Vf /etc/audit/audit.rules

If the string returned contains a "5" (ok: .......T., failure: S.5....T.), this is a finding.'
  desc 'fix', 'Obtain a copy of the appropriate audit package RPM file from CA Support and install it using RPM:

rpm -i "RPMFILE"'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71943r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71565'
  tag rid: 'SV-86189r1_rule'
  tag stig_id: 'CAGW-DM-000330'
  tag gtitle: 'SRG-APP-000505-NDM-000322'
  tag fix_id: 'F-77889r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
