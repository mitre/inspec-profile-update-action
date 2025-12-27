control 'SV-93681' do
  title 'The IBM z/VM System administrator must develop a notification routine for account management.'
  desc 'Information system accounts are utilized for identifying individual users or for identifying the operating system processes themselves. In order to detect and respond to events affecting user accessibility and system processing, operating systems must not only audit vital account actions but, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.'
  desc 'check', 'Ask the system administrator (SA) for documented procedures and routines for account management.

If there is no procedure or the procedure is not documented and filed with the ISSO, this is a finding.'
  desc 'fix', 'Develop processes, routines, and/or scripts for the notification of account management.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78563r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78975'
  tag rid: 'SV-93681r1_rule'
  tag stig_id: 'IBMZ-VM-002340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-85725r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
