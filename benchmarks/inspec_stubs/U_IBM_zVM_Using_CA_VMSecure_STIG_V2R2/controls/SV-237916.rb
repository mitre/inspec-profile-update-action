control 'SV-237916' do
  title 'CA VM:Secure product Config Delay LOG option must be set to 0.'
  desc 'IBM z/VM 6.4.0 made changes to obscure whether a logon is invalid due to the user ID or due to the password. Both the logon prompting sequence and the message HCPLGA050E were changed. However, DELAYLOG causes a delay for a logon with an invalid password that it does not cause when the user ID is invalid. Thus, if you are using DELAYLOG with z/VM 6.4.0, you can inadvertently let someone trying to break into your system know that it is the password that is invalid.'
  desc 'check', 'Display the CA VM:Secure product Config file.

If the "DELAYLOG" record does not exist, this is not a finding.

If the "DELAYLOG" record is set to "0", this is not a finding.'
  desc 'fix', 'Configure DELAYLOG = 0 or delete the "DELAYLOG" configuration file record.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41126r858964_chk'
  tag severity: 'medium'
  tag gid: 'V-237916'
  tag rid: 'SV-237916r858966_rule'
  tag stig_id: 'IBMZ-VM-000590'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-41085r858965_fix'
  tag 'documentable'
  tag legacy: ['SV-93585', 'V-78879']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
