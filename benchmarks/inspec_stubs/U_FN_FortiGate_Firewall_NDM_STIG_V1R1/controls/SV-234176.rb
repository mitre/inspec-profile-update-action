control 'SV-234176' do
  title 'The FortiGate device must generate audit records showing starting and ending time for administrator access to the system.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', %q(Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration log eventfilter | grep -i "event\|system'

The output should be:   
          set event enable
          set system enable

If the event and system parameters are set to disable, this is a finding.)
  desc 'fix', 'When Event Logging is enabled the device will audit starting and ending time for administrator access to the system. To enable event logging, log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:

     # config log eventfilter
     #    set event enable
     #    set system enable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37361r611715_chk'
  tag severity: 'medium'
  tag gid: 'V-234176'
  tag rid: 'SV-234176r628777_rule'
  tag stig_id: 'FGFW-ND-000085'
  tag gtitle: 'SRG-APP-000505-NDM-000322'
  tag fix_id: 'F-37326r611716_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
