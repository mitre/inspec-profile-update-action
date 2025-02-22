control 'SV-240429' do
  title 'The ypbind service must not be running if no network services utilizing it are enabled.'
  desc 'Disabling the "ypbind" service ensures the system is not acting as a client in a NIS or NIS+ domain when not required.'
  desc 'check', 'If network services are using the "ypbind" service, this is not applicable.

To check that the "ypbind" service is disabled in system boot configuration, run the following command: 

# chkconfig "ypbind" --list

Output should indicate the "ypbind" service has either not been installed, or has been disabled at all run levels, as shown in the example below: 

ypbind 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "ypbind" is disabled through current runtime configuration: 

# service ypbind status

If the service is disabled the command will return the following output: 

Checking for service ypbind unused

If the service is running, this is a finding.'
  desc 'fix', 'The "ypbind" service can be disabled with the following command: 

# chkconfig ypbind off'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43662r671026_chk'
  tag severity: 'medium'
  tag gid: 'V-240429'
  tag rid: 'SV-240429r671028_rule'
  tag stig_id: 'VRAU-SL-000540'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43621r671027_fix'
  tag 'documentable'
  tag legacy: ['SV-100285', 'V-89635']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
