control 'SV-255947' do
  title 'The Arista network device must limit the number of concurrent sessions to an organization-defined number for each administrator account and/or administrator account type.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to denial-of-service (DoS) attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions must be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Verify the device is configured to limit the number of concurrent management sessions with the following commands:

switch#sh run | section management ssh
management ssh
   connection limit 5
!

If the Arista network device is not configured to limit the number of SSH concurrent sessions, this is a finding.'
  desc 'fix', 'Configure the switch to limit SSH concurrent connections to the device with the following commands:

switch#configure
switch(config)#management ssh
switch(config-mgmt-ssh)#connection limit 5
switch(config-mgmt-ssh)#exit
switch#wr
!'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59623r882181_chk'
  tag severity: 'medium'
  tag gid: 'V-255947'
  tag rid: 'SV-255947r882183_rule'
  tag stig_id: 'ARST-ND-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-59566r882182_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
