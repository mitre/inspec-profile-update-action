control 'SV-254207' do
  title 'Nutanix AOS must be configured to disable user accounts after the password expires.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after zero days of inactivity.'
  desc 'check', 'Confirm Nutanix AOS is configured to disable user accounts after the password expires.

$ sudo grep -i inactive /etc/default/useradd
INACTIVE=0

If the value is not set to "0", is commented out, or is not defined, this is a finding.'
  desc 'fix', 'Configure the system to disable inactive user accounts after the password expires by running the following command.

$ sudo salt-call state.sls security/CVM/pamCVM'
  impact 0.3
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57692r846707_chk'
  tag severity: 'low'
  tag gid: 'V-254207'
  tag rid: 'SV-254207r846709_rule'
  tag stig_id: 'NUTX-OS-001220'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-57643r846708_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
