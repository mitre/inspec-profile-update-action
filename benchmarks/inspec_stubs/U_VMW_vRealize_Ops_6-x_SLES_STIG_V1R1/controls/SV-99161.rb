control 'SV-99161' do
  title 'The xinetd service must be disabled if no network services utilizing it are enabled.'
  desc 'The xinetd service provides a dedicated listener service for some programs, which is no longer necessary for commonly-used network services. Disabling it ensures that these uncommon services are not running, and also prevents attacks against xinetd itself.'
  desc 'check', 'If network services are using the "xinetd" service, this is not applicable.

To check that the "xinetd" service is disabled in system boot configuration, run the following command: 

# chkconfig "xinetd" --list

Output should indicate the "xinetd" service has either not been installed, or has been disabled at all run levels, as shown in the example below: 

xinetd 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "xinetd" is disabled through current runtime configuration: 

# service xinetd status

If the "xinetd" service is disabled the command will return the following output: 

Checking for service xinetd: unused

If the "xinetd" service is running, this is a finding.'
  desc 'fix', 'The "xinetd" service can be disabled with the following command: 

# chkconfig xinetd off'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88203r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88511'
  tag rid: 'SV-99161r1_rule'
  tag stig_id: 'VROM-SL-000505'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95253r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
