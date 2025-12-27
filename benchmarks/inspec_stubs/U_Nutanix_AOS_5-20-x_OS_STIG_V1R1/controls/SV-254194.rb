control 'SV-254194' do
  title 'Nutanix AOS must be configured to run SCMA daily.'
  desc 'The Nutanix platform leverages the use of the Security Configuration Management Automation (SCMA) framework to ensure secure configurations have not been altered from their desired state. If the SCMA framework is not run on a daily basis, changes to the secure baseline could be made, compromising multiple security functions and features on the operating system.'
  desc 'check', %q(Verify that the SCMA framework is set to run daily:

$ ncli cluster get-cvm-security-config | egrep 'Schedule'
Schedule : DAILY

If "Schedule" is not set to "DAILY", this is a finding.)
  desc 'fix', 'Set the SCMA framework to check the baseline daily:
$ sudo ncli cluster edit-cvm-security-params schedule=daily'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57679r846668_chk'
  tag severity: 'medium'
  tag gid: 'V-254194'
  tag rid: 'SV-254194r846670_rule'
  tag stig_id: 'NUTX-OS-001070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57630r846669_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
