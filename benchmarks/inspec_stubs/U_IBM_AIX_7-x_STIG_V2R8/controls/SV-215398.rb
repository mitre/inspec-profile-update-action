control 'SV-215398' do
  title 'AIX must set Stack Execution Disable (SED) system wide mode to all.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.

'
  desc 'check', 'From the command prompt, run the following command to display SED systemwide mode:

# sedmgr
Stack Execution Disable (SED) mode: all
SED configured in kernel: all

If the above command shows a systemwide SED mode other than "all", this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set the SED systemwide mode to select:
# sedmgr -m all

AIX has to be rebooted for the new SED mode to take effect.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16596r294645_chk'
  tag severity: 'medium'
  tag gid: 'V-215398'
  tag rid: 'SV-215398r853487_rule'
  tag stig_id: 'AIX7-00-003096'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-16594r294646_fix'
  tag satisfies: ['SRG-OS-000142-GPOS-00071', 'SRG-OS-000480-GPOS-00227', 'SRG-OS-000433-GPOS-00192']
  tag 'documentable'
  tag legacy: ['SV-101541', 'V-91443']
  tag cci: ['CCI-000366', 'CCI-001095', 'CCI-002824']
  tag nist: ['CM-6 b', 'SC-5 (2)', 'SI-16']
end
