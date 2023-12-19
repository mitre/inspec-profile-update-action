control 'SV-234178' do
  title 'The FortiGate device must generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., administrators or processes acting on behalf of administrators) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following commands:
     # show full-configuration log setting | grep -i anonymize
The output should be:         
          set user-anonymize disable

If the log setting user-anonymize is set to enable, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following commands:
     # config log setting
     # set user-anonymize disable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37363r611721_chk'
  tag severity: 'medium'
  tag gid: 'V-234178'
  tag rid: 'SV-234178r628777_rule'
  tag stig_id: 'FGFW-ND-000095'
  tag gtitle: 'SRG-APP-000100-NDM-000230'
  tag fix_id: 'F-37328r611722_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
