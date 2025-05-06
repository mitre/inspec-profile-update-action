control 'SV-30028' do
  title 'The password values must be set to meet the requirements in accordance with DoDI 8500.2 for DoD information systems processing sensitive information and above, and CJCSI 6510.01E (INFORMATION ASSURANCE (IA) AND COMPUTER NETWORK DEFENSE (CND)).'
  desc 'In accordance with DoDI 8500.2 for DoD information systems processing sensitive information and above and CJCSI 6510.01E (INFORMATION ASSURANCE (IA) AND COMPUTER NETWORK DEFENSE (CND)).. The following recommendations concerning password requirements are mandatory and apply equally to both classified and unclassified systems: (1) Passwords are to be fourteen (14) characters. (2) Passwords are to be a mix of upper and lower-case alphabetic, numeric, and special characters, including at least one of each. Special characters include the national characters (i.e., @, #, and $) and other non-alphabetic and non-numeric characters typically found on a keyboard. The improper setting of any of these fields, individually or in combination with another, can compromise the security of the processing environment. In addition, failure to establish standardized settings for the Hardware Management Console control options introduces the possibility of exposure during the migration process or contingency plan activation.'
  desc 'check', 'Have the System Administrator display the Password Profile Task  window on the Hardware Management Console and check that:

Passwords are to be a minimum of fourteen (14) characters in length.

Passwords are to be a mix of upper- and lower-case alphabetic, numeric, and special characters, including at least one of each. Special characters include the national characters (i.e., @, #, and $) and other non-alphabetic and non-numeric characters typically found on a keyboard.

Each character of the password is to be unique, prohibiting the use of repeating characters. 

Passwords are to contain no consecutive characters (e.g., 12, AB, etc.). 

If the Password Profile does not have the specifications for the above options then this is a FINDING.'
  desc 'fix', 'Have the System Administrator validate that the settings in the Password Profiles Window meet the following specifications:

Passwords are a minimum of fourteen (14) characters in length.

  Passwords are to be a mix of upper and lower-case alphabetic, numeric, and special characters, including at least one of each. Special characters include the national characters (i.e., @, #, and $) and other non-alphabetic and non-numeric characters typically found on a keyboard.

  Each character of the password is to be unique, prohibiting the use of repeating characters.

  Passwords are to contain no consecutive characters (e.g., 12, AB, etc.).'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24360'
  tag rid: 'SV-30028r2_rule'
  tag stig_id: 'HMC0140'
  tag gtitle: 'HMC0140'
  tag fix_id: 'F-26747r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'DCCS-1, DCCS-2, IAIA-1, IAIA-2'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000205', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']
end
