control 'SV-48161' do
  title 'Passwords must, at a minimum, be 14 characters.'
  desc 'Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies -> Password Policy.

If the value for the "Minimum password length," is less than 14 characters, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Minimum password length" to at least "14" characters.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6836'
  tag rid: 'SV-48161r1_rule'
  tag stig_id: 'WN08-AC-000007'
  tag gtitle: 'Minimum Password Length'
  tag fix_id: 'F-41299r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
