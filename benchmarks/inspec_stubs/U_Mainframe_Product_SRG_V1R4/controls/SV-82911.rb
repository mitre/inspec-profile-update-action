control 'SV-82911' do
  title 'Mainframe Products must audit nonlocal maintenance and diagnostic sessions audit events as defined in site security plan.'
  desc 'If events associated with nonlocal administrative access or diagnostic sessions are not logged and audited, a major tool for assessing and investigating attacks would not be available.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'If the Mainframe Product has no function or capability for nonlocal maintenance this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product does not audit the nonlocal maintenance and diagnostic sessions audit events defined in site security plan using external security manager files and/or SMF records, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to audit the nonlocal maintenance and diagnostic sessions audit events defined in site security plan using external security manager files and/or SMF records.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68953r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68421'
  tag rid: 'SV-82911r1_rule'
  tag stig_id: 'SRG-APP-000409-MFP-000257'
  tag gtitle: 'SRG-APP-000409-MFP-000257'
  tag fix_id: 'F-74537r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002884']
  tag nist: ['MA-4 (1) (a)']
end
