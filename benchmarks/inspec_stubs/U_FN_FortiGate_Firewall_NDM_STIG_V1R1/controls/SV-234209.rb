control 'SV-234209' do
  title 'The FortiGate device must not have any default manufacturer passwords when deployed.'
  desc 'Network devices not protected with strong password schemes provide the opportunity for anyone to crack the password and gain access to the device, which can result in loss of availability, confidentiality, or integrity of network traffic.

Many default vendor passwords are well known or are easily guessed; therefore, not removing them prior to deploying the network device into production provides an opportunity for a malicious user to gain unauthorized access to the device.'
  desc 'check', 'Attempt to log in to the FortiGate GUI using the username admin with the default (blank) password.

Attempt to log in to the CLI over SSH with the username admin with the default (blank) password.

If either of these logins are successful, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following commands:
     # config system admin
     # edit admin
     # set password {password}
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37394r611814_chk'
  tag severity: 'medium'
  tag gid: 'V-234209'
  tag rid: 'SV-234209r628777_rule'
  tag stig_id: 'FGFW-ND-000250'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-37359r611815_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
