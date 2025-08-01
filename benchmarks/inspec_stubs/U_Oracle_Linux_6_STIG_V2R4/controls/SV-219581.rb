control 'SV-219581' do
  title 'The Bluetooth service must be disabled.'
  desc 'Disabling the "bluetooth" service prevents the system from attempting connections to Bluetooth devices, which entails some security risk. Nevertheless, variation in this risk decision may be expected due to the utility of Bluetooth connectivity and its limited range.'
  desc 'check', 'To check that the "bluetooth" service is disabled in system boot configuration, run the following command:

# chkconfig "bluetooth" --list

Output should indicate the "bluetooth" service has either not been installed or has been disabled at all runlevels, as shown in the example below:

# chkconfig "bluetooth" --list
"bluetooth" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

If the service is configured to run, this is a finding.'
  desc 'fix', 'The "bluetooth" service can be disabled with the following command: 

# chkconfig bluetooth off

# service bluetooth stop'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21306r462355_chk'
  tag severity: 'medium'
  tag gid: 'V-219581'
  tag rid: 'SV-219581r603263_rule'
  tag stig_id: 'OL6-00-000331'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-21305r462356_fix'
  tag 'documentable'
  tag legacy: ['SV-65337', 'V-51127']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
