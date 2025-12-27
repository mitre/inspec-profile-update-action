control 'SV-233243' do
  title 'The container platform must perform verification of the correct operation of security functions: upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.'
  desc 'Without verification, security functions may not operate correctly and this failure may go unnoticed within the container platform.

Security functions are responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include, for example, electronic alerts to organization-defined role.'
  desc 'check', 'Review container platform documentation.

Verify that the container platform is configured to perform verification of the correct operation of security functions, which may include the valid connection to an external security manager (ESM), upon product startup/restart, by a user with privileged access, and/or every 30 days.

If it is not, this is a finding.'
  desc 'fix', 'Configure the container platform to perform verification of the correct operation of security functions, which may include the connection validation, upon product startup/restart, or by a user with privileged access, and/or every 30 days.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36179r599676_chk'
  tag severity: 'medium'
  tag gid: 'V-233243'
  tag rid: 'SV-233243r599708_rule'
  tag stig_id: 'SRG-APP-000473-CTR-001175'
  tag gtitle: 'SRG-APP-000473'
  tag fix_id: 'F-36147r599366_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
