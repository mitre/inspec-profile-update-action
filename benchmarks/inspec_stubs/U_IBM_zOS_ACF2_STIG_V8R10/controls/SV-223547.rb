control 'SV-223547' do
  title 'IBM z/OS SMF collection files (system MANx data sets or LOGSTREAM DASD) must have storage capacity to store at least one weeks worth of audit data.'
  desc 'In order to ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', "Review the SMF dump procedure in the system.

If the output data sets in the procedure have storage capacity to store at least one week's worth of audit data, this is not a finding."
  desc 'fix', "Make sure output file and dump procedures allow storage capacity to store one week's worth of audit data."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25220r500776_chk'
  tag severity: 'medium'
  tag gid: 'V-223547'
  tag rid: 'SV-223547r877391_rule'
  tag stig_id: 'ACF2-OS-000110'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-25208r500777_fix'
  tag 'documentable'
  tag legacy: ['SV-106903', 'V-97799']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
