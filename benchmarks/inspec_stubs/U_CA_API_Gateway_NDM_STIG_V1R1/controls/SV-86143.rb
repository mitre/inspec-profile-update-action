control 'SV-86143' do
  title 'The CA API Gateway must be installed on Red Hat Enterprise Linux (RHEL) Version 6.7 or higher.'
  desc 'The API Gateway (Appliance version) depends on specific RHEL capabilities for the security, logging, and auditing subsystems. Installation on alternative or older RHEL versions may create vulnerabilities.'
  desc 'check', 'Verify the CA API Gateway is installed on Red Hat Enterprise Linux (RHEL) Version 6.7 or higher.

If the CA API Gateway is not installed on Red Hat Enterprise Linux (RHEL) Version 6.7 or higher, this is a finding.'
  desc 'fix', 'Configure the CA API Gateway to be installed on Red Hat Enterprise Linux (RHEL) Version 6.7 or higher.'
  impact 0.7
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71891r1_chk'
  tag severity: 'high'
  tag gid: 'V-71519'
  tag rid: 'SV-86143r1_rule'
  tag stig_id: 'CAGW-DM-000100'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-77839r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
