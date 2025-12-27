control 'SV-82549' do
  title 'The A10 Networks ADC must reveal error messages only to authorized individuals (ISSO, ISSM, and SA).'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state. Additionally, sensitive account information must not be revealed through error messages to unauthorized personnel or their designated representatives.

In the A10 Networks ADC, the audit log is maintained in a separate file separate from the system log. Access to the audit log is role-based. The audit log messages that are displayed for an admin depend upon that administrator’s role (privilege level). Administrators with Root, Read Write, or Read Only privileges who view the audit log can view all the messages, for all system partitions."
  desc 'check', 'Review the device configuration.

Enter the following command to view detailed information about the administrative accounts:
show admin detail

The output of this command will show the Access type, Privilege level, and GUI role, among other parameters. 

If persons other than other than the authorized individuals (ISSO, ISSM, and SA) have Root, Read Write, or Read Only privileges, this is a finding.'
  desc 'fix', 'Do not assign anyone who is not the ISSO, ISSM, and authorized System Administrators to be Administrators with Root, Read Write, or Read Only privileges. Do not configure accounts with Root, Read Write, or Read Only privileges for anyone other than the authorized individuals (ISSO, ISSM, and SA).'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68619r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68059'
  tag rid: 'SV-82549r1_rule'
  tag stig_id: 'AADC-NM-000076'
  tag gtitle: 'SRG-APP-000267-NDM-000273'
  tag fix_id: 'F-74175r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
