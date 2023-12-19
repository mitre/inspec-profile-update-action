control 'SV-99163' do
  title 'The ypbind service must not be running if no network services utilizing it are enabled.'
  desc 'Disabling the "ypbind" service ensures the SLES for vRealize is not acting as a client in a NIS or NIS+ domain when not required.'
  desc 'check', 'If network services are using the "ypbind" service, this is not applicable.

To check that the "ypbind" service is disabled in system boot configuration, run the following command: 

# chkconfig "ypbind" --list

Output should indicate the "ypbind" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

ypbind 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "ypbind" is disabled through current runtime configuration: 

# service ypbind status

If the "ypbind" service is disabled the command will return the following output: 

Checking for service ypbind unused

If the "ypbind" service is running, this is a finding.'
  desc 'fix', 'The "ypbind" service can be disabled with the following command: 

# chkconfig ypbind off'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88205r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88513'
  tag rid: 'SV-99163r1_rule'
  tag stig_id: 'VROM-SL-000510'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95255r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
