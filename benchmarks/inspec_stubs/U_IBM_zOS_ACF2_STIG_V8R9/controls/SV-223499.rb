control 'SV-223499' do
  title 'CA-ACF2 PWPHRASE GSO record must be properly defined.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'From the ISPF Command Screen enter:
ACF
SET CONTROL(GSO)
LIST PWPHRASE
If the following options are in effect, this is not a finding.

If any of the options deviate from the following, this is a finding.

The GSO PWPHRASE record will conform to the following requirements.

ALPHA(1 or greater)
HISTORY(10-32)
MAXDAYS(1-60)
MINDAYS(1)
MINLEN(15-100)
NUMERIC(1 or greater)
SPECIAL(1 or greater)
SPECLIST(character list)
WARNDAYS(1-10)

Note: The SPECLIST special characters will be specified at a minimum. Characters will conform to the allowable list defined in CA ACF2 for z/OS Administration Guide.'
  desc 'fix', 'Configure the PWPHRASE GSO values to be set to the values specified.

Ensure the GSO PWPHRASE record values conform to the following requirements:

ALPHA(1 or greater)
HISTORY(10-32)
MAXDAYS(1-60)
MINDAYS(1)
MINLEN(15-100)
NUMERIC(1 or greater)
SPECIAL(1 or greater)
SPECLIST(character list)
WARNDAYS(1-10)

Note: The SPECLIST special characters will be specified at a minimum. Characters will conform to the allowable list defined in CA ACF2 for z/OS Administration Guide.

Example:
SET C(GSO)
INSERT PWPHRASE NOALLOW ALPHA(1) HISTORY(10) MAXDAYS(60) MINDAYS(1) MINLEN(15) NUMERIC(1) SPECIAL(1) SPECLIST(& * =) WARNDAYS(10)

F ACF2,REFRESH(PWPHRASE)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25172r695421_chk'
  tag severity: 'medium'
  tag gid: 'V-223499'
  tag rid: 'SV-223499r695422_rule'
  tag stig_id: 'ACF2-ES-000810'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-25160r504598_fix'
  tag 'documentable'
  tag legacy: ['V-97697', 'SV-106801']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
