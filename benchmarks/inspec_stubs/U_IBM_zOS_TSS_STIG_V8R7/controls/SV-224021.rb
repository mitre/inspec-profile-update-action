control 'SV-224021' do
  title 'IBM z/OS SMF collection files (system MANx data sets or LOGSTREAM DASD) must have storage capacity to store at least one weeks worth of audit data.'
  desc 'In order to ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', "Review the SMF dump procedure in there system.

If the output data sets in the procedure have storage capacity to store at least one weeks' worth of audit data, this is not a finding."
  desc 'fix', 'The system Link Pack Area (LPA) is the component of MVS that maintains core operating system functions resident in main storage. A security concern exists when libraries from which LPA modules are obtained require APF authorization.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25694r516462_chk'
  tag severity: 'medium'
  tag gid: 'V-224021'
  tag rid: 'SV-224021r856120_rule'
  tag stig_id: 'TSS0-OS-000240'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-25682r516463_fix'
  tag 'documentable'
  tag legacy: ['SV-107853', 'V-98749']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
