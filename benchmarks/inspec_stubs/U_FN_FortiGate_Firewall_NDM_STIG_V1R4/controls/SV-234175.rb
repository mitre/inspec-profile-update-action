control 'SV-234175' do
  title 'The FortiGate device must generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', "Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration log eventfilter | grep -i 'event\\|system'

The output should be:   
          set event enable
          set system enable

If the event and system parameters are set to disable, this is a finding."
  desc 'fix', 'When Event Logging is enabled, the device will audit privileged activities or other system-level access. To enable event logging, log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:

     # config log eventfilter
     #    set event enable
     #    set system enable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37360r835176_chk'
  tag severity: 'medium'
  tag gid: 'V-234175'
  tag rid: 'SV-234175r879875_rule'
  tag stig_id: 'FGFW-ND-000080'
  tag gtitle: 'SRG-APP-000504-NDM-000321'
  tag fix_id: 'F-37325r611713_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
