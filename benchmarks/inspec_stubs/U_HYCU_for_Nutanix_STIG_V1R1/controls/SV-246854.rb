control 'SV-246854' do
  title 'The HYCU VM console must not have any default manufacturer passwords when deployed.'
  desc 'Virtual Machines not protected with strong password schemes provide the opportunity for anyone to crack the password and gain access to the device, which can result in loss of availability, confidentiality, or integrity of network traffic. Many default vendor passwords are well known or are easily guessed; therefore, not removing them prior to deploying the network device into production provides an opportunity for a malicious user to gain unauthorized access to the device.'
  desc 'check', 'Log on to the HYCU VM console. 

Log on to the HYCU Web UI with the following default credentials: 
Username: "hycu"
Password: "hycu/4u"

Log on to the HYCU Web UI with the following default credentials:
Username: "admin"
Password: "admin"

If the logon with either of the default credentials is successful, this is a finding.'
  desc 'fix', 'Log on to the HYCU VM console with the following username and password:
Username: "hycu" 
Password: "hycu/4u"

Run the passwd command to change the default password.
 
In the HYCU Web UI, log on and change the password by selecting the Admin account in the upper-right corner and changing the password. You will be logged off and prompted to log on with the updated credentials.'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50286r768224_chk'
  tag severity: 'medium'
  tag gid: 'V-246854'
  tag rid: 'SV-246854r768226_rule'
  tag stig_id: 'HYCU-IA-000006'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-50240r768225_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
