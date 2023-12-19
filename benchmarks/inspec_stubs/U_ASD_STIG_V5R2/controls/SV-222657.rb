control 'SV-222657' do
  title 'The application development team must provide an application incident response plan.'
  desc 'An application incident response process is managed by the development team and should include a method for individuals to submit potential security vulnerabilities to the development or maintenance team. 

The plan should dictate what is to be done with the reported vulnerabilities. Reported vulnerabilities must be tracked throughout the process to ensure they are triaged, corrected, and tested. The corresponding update is released to the user community and the user community is notified of the availability of the application update.

Without an established application incident management plan and process, discovered issues and vulnerabilities will go unreported.   Vulnerabilities will not be triaged and managed, and there may be delays in corrective actions.

Information on how to submit bug and vulnerability reports must also be included in the application design document or configuration guide.

This requirement is meant to be applied when reviewing an application with the development team.'
  desc 'check', 'If the application is a COTS application and the development team is not accessible to interview this requirement is not applicable.

Interview the application development team members. Request and review the application incident response plan. 

Ensure the plan includes an implemented process that:

- Tracks reported vulnerabilities and bugs
- Confirms reported vulnerabilities and bugs
- Tracks remediation effort
- Notifies application users of available updates that address the reported issues.

If the application incident response plan does not exist and at a minimum does not implement the aforementioned processes, this is a finding.'
  desc 'fix', 'The development team creates an application incident response plan documenting and establishing a process that at a minimum:

- Tracks reported vulnerabilities and bugs
- Confirms reported vulnerabilities and bugs
- Tracks remediation effort
- Notifies application users of available updates that address the reported issues.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36259r602340_chk'
  tag severity: 'medium'
  tag gid: 'V-222657'
  tag rid: 'SV-222657r864582_rule'
  tag stig_id: 'APSC-DV-003236'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36223r864582_fix'
  tag 'documentable'
  tag legacy: ['SV-85015', 'V-70393']
  tag cci: ['CCI-003289']
  tag nist: ['SA-15 (10)']
end
