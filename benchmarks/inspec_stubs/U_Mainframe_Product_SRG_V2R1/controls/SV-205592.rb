control 'SV-205592' do
  title 'The Mainframe Product must perform verification of the correct operation of security functions upon system startup and/or restart; upon command by a user with privileged access; and/or every 30 days.'
  desc 'Without verification, security functions may not operate correctly and this failure may go unnoticed. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing.'
  desc 'check', 'Examine the installation, configuration, and product documentation.

If the Mainframe Product verification of the correct operation of security functions, which may include the valid connection to an external security manager (ESM), is not performed upon product startup/restart, or by a user with privileged access, and/or every 30 days, this is a finding.'
  desc 'fix', 'If necessary, configure the Mainframe Product configuration and installation settings to perform verification of the correct operation of security functions, which may include the valid connection to an ESM, upon product startup/restart, or by a user with privileged access, and/or every 30 days.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5858r300003_chk'
  tag severity: 'medium'
  tag gid: 'V-205592'
  tag rid: 'SV-205592r851357_rule'
  tag stig_id: 'SRG-APP-000473-MFP-000371'
  tag gtitle: 'SRG-APP-000473'
  tag fix_id: 'F-5858r539613_fix'
  tag 'documentable'
  tag legacy: ['SV-82985', 'V-68495']
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
