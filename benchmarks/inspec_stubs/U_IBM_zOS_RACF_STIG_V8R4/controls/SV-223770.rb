control 'SV-223770' do
  title 'IBM z/OS SMF collection files (system MANx datasets or LOGSTREAM DASD) must have storage capacity to store at least one weeks worth of audit data.'
  desc 'In order to ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', "Review the SMF dump procedure in there system.

If the output datasets in the procedure have storage capacity to store at least one week's worth of audit data, this is not a finding."
  desc 'fix', "Make sure output file and dump procedures allow storage capacity to store one week's worth of audit data."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25443r514998_chk'
  tag severity: 'medium'
  tag gid: 'V-223770'
  tag rid: 'SV-223770r604139_rule'
  tag stig_id: 'RACF-OS-000140'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-25431r514999_fix'
  tag 'documentable'
  tag legacy: ['V-98247', 'SV-107351']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
