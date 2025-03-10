control 'SV-102381' do
  title 'The SEL-2740S must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.'
  desc 'check', 'Review the configuration node of the SEL-2740S in the flow controller and verify the alarm contact behavior is configured as a log service under All Categories in the configuration object for the desired switch.  

If the switch is not configured to alert the ISSO and SA in the event of an audit processing failure, this is a finding.'
  desc 'fix', 'On commissioning the SEL-2740S, enter the IP address, subnet mask, flow controller IP address, default gateway, and host name. Select the severity level desired for the alarm contact in the log services for the configuration node.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91589r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92293'
  tag rid: 'SV-102381r1_rule'
  tag stig_id: 'SELS-ND-000340'
  tag gtitle: 'SRG-APP-000108-NDM-000232'
  tag fix_id: 'F-98531r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
