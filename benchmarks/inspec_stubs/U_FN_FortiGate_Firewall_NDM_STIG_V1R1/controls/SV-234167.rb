control 'SV-234167' do
  title 'The FortiGate device must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', %q(Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration log eventfilter | grep -i "event\|system'

The output should be:   
          set event enable
          set system enable

If the event and system parameters are set to disable, this is a finding.)
  desc 'fix', 'This fix can be performed on the FortiGate GUI or on the CLI. 
Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:

     # config log eventfilter
     #    set event enable
     #    set system enable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37352r611688_chk'
  tag severity: 'medium'
  tag gid: 'V-234167'
  tag rid: 'SV-234167r628777_rule'
  tag stig_id: 'FGFW-ND-000040'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-37317r611689_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
