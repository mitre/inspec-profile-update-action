control 'SV-208797' do
  title 'The Red Hat Network Service (rhnsd) service must not be running, unless it is being used to query the Oracle Unbreakable Linux Network for updates and information.'
  desc 'Although systems management and patching is extremely important to system security, management by a system outside the enterprise enclave is not desirable for some environments. However, if the system needs to communicate with the Oracle Unbreakable Linux Network for updates or information, then the "rhnsd" daemon can remain on.'
  desc 'check', 'If the system needs to automatically communicate with the Oracle Unbreakable Linux Network for updates or information, then this is not applicable.

To check that the "rhnsd" service is disabled in system boot configuration, run the following command: 

# chkconfig "rhnsd" --list

Output should indicate the "rhnsd" service has either not been installed or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "rhnsd" --list
"rhnsd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "rhnsd" is disabled through current runtime configuration: 

# service rhnsd status

If the service is disabled, the command will return the following output: 

rhnsd is stopped

If the service is running, this is a finding.'
  desc 'fix', 'This service automatically queries the Oracle Unbreakable Linux Network service to determine whether there are any software updates or related information.  The "rhnsd" service can be disabled with the following commands: 

# chkconfig rhnsd off
# service rhnsd stop'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9050r357371_chk'
  tag severity: 'low'
  tag gid: 'V-208797'
  tag rid: 'SV-208797r793582_rule'
  tag stig_id: 'OL6-00-000009'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-9050r357372_fix'
  tag 'documentable'
  tag legacy: ['SV-64899', 'V-50693']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
