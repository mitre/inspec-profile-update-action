control 'SV-237058' do
  title 'The A10 Networks ADC must reveal error messages only to authorized individuals (ISSO, ISSM, and SA).'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can give configuration details about the network element. Limiting access to system logs and administrative consoles to authorized personnel will help to mitigate this risk. However, user feedback and error messages should also be restricted by type and content in accordance with security best practices (e.g., ICMP messages).

In the A10 Networks ADC, the audit log is maintained in a separate file separate from the system log. Access to the audit log is role-based. The audit log messages that are displayed for an admin depend upon that administrator’s role (privilege level). Administrators with Root, Read Write, or Read Only privileges who view the audit log can view all the messages, for all system partitions."
  desc 'check', 'Review the device configuration.

Enter the following command to view detailed information about the administrative accounts:
show admin detail

The output of this command will show the Access type, the Privilege level, and GUI role among other parameters. 

If persons other than other than the authorized individuals (ISSO, ISSM, and SA) have Root, Read Write, or Read Only privileges, this is a finding.'
  desc 'fix', 'Do not assign anyone who is not the ISSO, ISSM, and authorized System Administrators to be Administrators with Root, Read Write, or Read Only privileges. Do not configure accounts with Root, Read Write, or Read Only privileges for anyone other than the authorized individuals (ISSO, ISSM, and SA).'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40277r639619_chk'
  tag severity: 'medium'
  tag gid: 'V-237058'
  tag rid: 'SV-237058r639621_rule'
  tag stig_id: 'AADC-AG-000123'
  tag gtitle: 'SRG-NET-000402-ALG-000130'
  tag fix_id: 'F-40240r639620_fix'
  tag 'documentable'
  tag legacy: ['SV-82505', 'V-68015']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
